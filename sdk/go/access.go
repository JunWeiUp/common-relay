package relay

import (
	"errors"
	"net/http"
)

// AccessHeader carries the relay server's access password on every request.
const AccessHeader = "Relay-Access"

var errAccessPassword = errors.New("invalid relay access password: 8-128 printable ASCII characters without spaces")

// validAccessPassword accepts "" (header omitted) or 8..128 bytes in 0x21..0x7e.
func validAccessPassword(p string) error {
	if p == "" {
		return nil
	}
	if len(p) < 8 || len(p) > 128 {
		return errAccessPassword
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] > 0x7e {
			return errAccessPassword
		}
	}
	return nil
}

func setAccess(h http.Header, p string) {
	if p != "" {
		h.Set(AccessHeader, p)
	}
}
