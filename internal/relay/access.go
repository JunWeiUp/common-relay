package relay

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strings"
)

// AccessHeader carries the server-wide access password on every /relay/v1 request.
const AccessHeader = "Relay-Access"

// ValidAccessPassword reports whether p is 8..128 printable ASCII characters (0x21..0x7e).
func ValidAccessPassword(p string) bool {
	if len(p) < 8 || len(p) > 128 {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] > 0x7e {
			return false
		}
	}
	return true
}

// AccessPasswordHash returns lowercase hex SHA-256 of the password.
func AccessPasswordHash(p string) string {
	h := sha256.Sum256([]byte(p))
	return hex.EncodeToString(h[:])
}

// LoadAccessHash reads a file containing only the lowercase hex SHA-256 of the password.
func LoadAccessHash(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v := strings.TrimSpace(string(b))
	raw, err := hex.DecodeString(v)
	if err != nil || len(raw) != sha256.Size || v != strings.ToLower(v) {
		return nil, errors.New("access password file must contain lowercase hex SHA-256")
	}
	return raw, nil
}

func (s *Server) requireAccess(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.AccessHash != nil {
			got := sha256.Sum256([]byte(r.Header.Get(AccessHeader)))
			if subtle.ConstantTimeCompare(got[:], s.AccessHash) != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}
