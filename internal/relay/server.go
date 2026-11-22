package relay

import (
	"net/http"
	"strings"
	"sync"
)

type SyncedGroupMember struct {
	ID        string
	Name      string
	PublicKey string
	TokenHash string
	Manager   bool
}

// Server hosts the signed group ledger (/v2/group, /v2/enroll) and the resumable
// encrypted file plane (/v2/files). Device sessions live on the v2 pipe; group
// changes reach it through OnGroupSynced.
type Server struct {
	Usage           *Usage // per-app calls into the ledger/files code (exposed via /v2/admin/metrics)
	SelfServiceApps map[string]bool
	AccessHash      []byte // SHA-256 of the required Relay-Access password; nil disables the check
	accessMu        sync.RWMutex
	Store           *Store
	OnGroupSynced   func(app, group, groupName string, members []SyncedGroupMember, removed []string, closed bool, revision int)
	// OnlinePeers reports which devices of a group currently hold a live session.
	OnlinePeers func(app, group string) []string
	fileLocksMu sync.Mutex
	fileLocks   map[string]*fileLock
	DiskReserve uint64
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

// Healthz reports 200 while the ledger database answers.
func (s *Server) Healthz(w http.ResponseWriter, _ *http.Request) {
	if s.Store.DB.Ping() != nil {
		http.Error(w, "unavailable", 503)
		return
	}
	w.Write([]byte("ok\n"))
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
