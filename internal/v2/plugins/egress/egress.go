// Package egress implements a trust-gated outbound event notification plugin.
//
// When bound to a bridge_allowed Space via /v2/admin/plugins/egress/{mount},
// it subscribes to committed Box change events and asynchronously POSTs a
// metadata-only JSON envelope (never payload bytes) to target_url with an
// optional HMAC-SHA256 signature.
package egress

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JunWeiUp/common-relay/internal/v2/core"
	"github.com/JunWeiUp/common-relay/internal/v2/plugin"
)

const (
	defaultTimeoutSec = 5
	maxTimeoutSec     = 30
	queueCapacity     = 256
)

type config struct {
	TargetURL       string   `json:"target_url"`
	HMACSecret      string   `json:"hmac_secret,omitempty"`
	BoxFilter       string   `json:"box_filter,omitempty"`
	Events          []string `json:"events,omitempty"`
	TimeoutSec      int      `json:"timeout_sec,omitempty"`
	AllowPrivateURL bool     `json:"allow_private_url,omitempty"`
}

type eventJob struct {
	SpaceID  string `json:"space"`
	BoxName  string `json:"box"`
	Event    string `json:"event"`
	Ref      string `json:"ref"`
	Seq      int64  `json:"seq"`
	At       int64  `json:"timestamp"`
}

type Plugin struct {
	host *plugin.Host

	mu     sync.Mutex
	closed bool
	ch     chan eventJob
	done   chan struct{}
	client *http.Client
}

func New() *Plugin {
	return &Plugin{
		ch:     make(chan eventJob, queueCapacity),
		done:   make(chan struct{}),
		client: &http.Client{Timeout: maxTimeoutSec * time.Second},
	}
}

func (p *Plugin) ID() string                     { return "egress" }
func (p *Plugin) RequiredTrust() core.TrustLevel { return core.TrustBridgeAllowed }

func (p *Plugin) ConfigSchema() []plugin.FieldSpec {
	return []plugin.FieldSpec{
		{Key: "target_url", Type: "string", Required: true, Description: "HTTP(S) webhook destination URL (metadata-only JSON POST)"},
		{Key: "hmac_secret", Type: "string", Secret: true, Description: "optional HMAC-SHA256 signing key (16-256 chars)"},
		{Key: "box_filter", Type: "string", Description: "optional box name filter (empty matches all boxes in the Space)"},
		{Key: "events", Type: "string_list", Description: "event types to forward: item, object, object_deleted (default: item, object)"},
		{Key: "timeout_sec", Type: "int", Description: fmt.Sprintf("HTTP timeout in seconds (1-%d, default %d)", maxTimeoutSec, defaultTimeoutSec)},
		{Key: "allow_private_url", Type: "bool", Description: "allow loopback/private IP target_url (default false)"},
	}
}

func (p *Plugin) ValidateConfig(cfg map[string]any) error {
	known := map[string]bool{}
	for _, f := range p.ConfigSchema() {
		known[f.Key] = true
	}
	for k := range cfg {
		if !known[k] {
			return fmt.Errorf("unknown egress config key %q", k)
		}
	}
	rawURL, _ := cfg["target_url"].(string)
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return errors.New("target_url is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("target_url must be a valid http(s) URL")
	}
	allowPriv, _ := cfg["allow_private_url"].(bool)
	if !allowPriv && isPrivateHost(u.Hostname()) {
		return errors.New("target_url points to a loopback or private address (set allow_private_url=true to permit)")
	}
	if v, ok := cfg["hmac_secret"]; ok {
		s, _ := v.(string)
		if len(s) < 16 || len(s) > 256 {
			return errors.New("hmac_secret must be 16-256 characters")
		}
	}
	if v, ok := cfg["box_filter"]; ok {
		s, ok := v.(string)
		if !ok || len(s) > 120 {
			return errors.New("box_filter must be a valid box name string")
		}
	}
	if v, ok := cfg["events"]; ok {
		list, ok := v.([]any)
		if !ok {
			return errors.New("events must be a list of strings")
		}
		for _, it := range list {
			s, ok := it.(string)
			if !ok || (s != "item" && s != "object" && s != "object_deleted") {
				return fmt.Errorf("invalid egress event %v", it)
			}
		}
	}
	if v, ok := cfg["timeout_sec"]; ok {
		n, ok := v.(float64)
		if !ok || n < 1 || n > maxTimeoutSec {
			return fmt.Errorf("timeout_sec must be 1..%d", maxTimeoutSec)
		}
	}
	return nil
}

func isPrivateHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if h == "localhost" || strings.HasSuffix(h, ".localhost") || strings.HasSuffix(h, ".local") {
		return true
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func (p *Plugin) Init(host *plugin.Host) error {
	p.host = host
	host.Store().AddBoxChangeListener(func(spaceID, boxName, event, ref string, seqOrVer int64) {
		p.enqueue(eventJob{
			SpaceID: spaceID,
			BoxName: boxName,
			Event:   event,
			Ref:     ref,
			Seq:     seqOrVer,
			At:      time.Now().Unix(),
		})
	})
	go p.worker()
	return nil
}

func (p *Plugin) Close() error {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.ch)
	}
	p.mu.Unlock()
	<-p.done
	return nil
}

func (p *Plugin) EdgeHandler(_ *plugin.Host) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "egress is an outbound-only plugin", http.StatusMethodNotAllowed)
	})
}

func (p *Plugin) enqueue(job eventJob) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	select {
	case p.ch <- job:
	default:
		// Bounded queue: drop under sustained downstream outage rather than blocking Box writes.
	}
}

func (p *Plugin) worker() {
	defer close(p.done)
	for job := range p.ch {
		p.dispatch(job)
	}
}

func (p *Plugin) dispatch(job eventJob) {
	if p.host == nil {
		return
	}
	bindings, err := p.host.ListBindings(p.ID())
	if err != nil || len(bindings) == 0 {
		return
	}
	for _, pub := range bindings {
		if !pub.Enabled || pub.SpaceID != job.SpaceID {
			continue
		}
		b, sp, err := p.host.LookupBinding(p.ID(), pub.Mount)
		if err != nil || !sp.TrustLevel.Allows(p.RequiredTrust()) {
			continue
		}
		var cfg config
		if json.Unmarshal([]byte(b.ConfigJSON), &cfg) != nil || cfg.TargetURL == "" {
			continue
		}
		if cfg.BoxFilter != "" && cfg.BoxFilter != job.BoxName {
			continue
		}
		if !eventAllowed(cfg.Events, job.Event) {
			continue
		}
		p.deliver(cfg, job)
	}
}

func eventAllowed(allowed []string, ev string) bool {
	if len(allowed) == 0 {
		return ev == "item" || ev == "object"
	}
	for _, a := range allowed {
		if a == ev {
			return true
		}
	}
	return false
}

func (p *Plugin) deliver(cfg config, job eventJob) {
	body, err := json.Marshal(job)
	if err != nil {
		return
	}
	timeout := defaultTimeoutSec
	if cfg.TimeoutSec > 0 && cfg.TimeoutSec <= maxTimeoutSec {
		timeout = cfg.TimeoutSec
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.TargetURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	ts := strconv.FormatInt(job.At, 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Relay-Event", job.Event)
	req.Header.Set("X-Relay-Space", job.SpaceID)
	req.Header.Set("X-Relay-Timestamp", ts)
	if cfg.HMACSecret != "" {
		mac := hmac.New(sha256.New, []byte(cfg.HMACSecret))
		mac.Write([]byte(ts))
		mac.Write([]byte("."))
		mac.Write(body)
		req.Header.Set("X-Relay-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := p.client.Do(req)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}
}
