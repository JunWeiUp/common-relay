package ledger

import (
	"log"
	"net/http"
	"strings"
	"sync"
)

// Hub is the part of the v2 pipe the ledger drives after a membership commit.
type Hub interface {
	OnlineDevices(spaceID string) []string
	NotifyGroupChanged(spaceID string, revision int)
	DisconnectDevice(deviceID string)
}

// Server serves the signed group ledger (/v2/group, /v2/enroll) and the
// resumable encrypted file plane (/v2/files). Device sessions live on the v2
// pipe (Hub); membership is mirrored into v2 spaces inside each ledger commit.
type Server struct {
	Usage           *Usage // per-app calls (exposed via /v2/admin/metrics "ledger")
	SelfServiceApps map[string]bool
	AccessHash      []byte // SHA-256 of the required Relay-Access password; nil disables the check
	accessMu        sync.RWMutex
	Store           *Store
	Hub             Hub // optional; nil in unit tests
	fileLocksMu     sync.Mutex
	fileLocks       map[string]*fileLock
	DiskReserve     uint64
}

func New(s *Store) *Server {
	return &Server{Usage: &Usage{}, Store: s, fileLocks: map[string]*fileLock{}, DiskReserve: 2 << 30}
}

// Handler serves /v2/group, /v2/group/*, /v2/enroll/*, /v2/files and /v2/files/*,
// all behind the Relay-Access guard. Anything else is 404.
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("/v2/group", s.requireAccess(s.groups))
	m.HandleFunc("/v2/group/", s.requireAccess(s.groups))
	m.HandleFunc("/v2/enroll/", s.requireAccess(s.groups))
	m.HandleFunc("/v2/files", s.requireAccess(s.files))
	m.HandleFunc("/v2/files/", s.requireAccess(s.files))
	return m
}

func (s *Server) auth(r *http.Request) (Device, error) {
	v := r.Header.Get("Authorization")
	if !strings.HasPrefix(v, "Bearer ") {
		return Device{}, ErrDenied
	}
	d, err := s.Store.Authenticate(strings.TrimPrefix(v, "Bearer "))
	if err == nil {
		s.Usage.record(d.App, r)
	}
	return d, err
}

// committed tells live sessions about a committed membership change: removed
// devices lose their session, a disbanded group drops everyone, otherwise
// online members get group.changed. projected is false when the space mirror
// was skipped (e.g. its ID belongs to an admin space); nothing is pushed then.
func (s *Server) committed(g GroupState, removed []Member, projected bool) {
	if s.Hub == nil || !projected {
		return
	}
	for _, m := range removed {
		s.Hub.DisconnectDevice(m.Device)
	}
	if g.Closed {
		for _, id := range s.Hub.OnlineDevices(g.Group) {
			s.Hub.DisconnectDevice(id)
		}
		return
	}
	s.Hub.NotifyGroupChanged(g.Group, g.Revision)
}

func logProjection(g GroupState, err error) {
	log.Printf("ledger: space mirror for %s/%s skipped: %v", g.App, g.Group, err)
}
