package relay

import (
	"bytes"
	"strconv"
	"unicode/utf8"
)

// Signed payloads are re-verified by four SDKs whose JSON parsers disagree on
// duplicate keys, key case, unknown fields, null, number forms and lone
// surrogates. Accept one unambiguous shape only, so the relay never stores a
// record that a client reads differently or cannot read at all. The SDKs run
// the same byte-level scan (protocol/README.md, "严格载荷").
type payloadField struct {
	kind     byte // s string, i safe integer, b bool, m member, M member list
	required bool
}

var (
	payloadMemberSchema  = map[string]payloadField{"device": {'s', true}, "name": {'s', true}, "public_key": {'s', true}, "signing_key": {'s', true}, "manager": {'b', true}}
	payloadStateSchema   = map[string]payloadField{"closed": {'b', false}, "name": {'s', false}, "version": {'i', true}, "app": {'s', true}, "group": {'s', true}, "revision": {'i', true}, "previous": {'s', true}, "members": {'M', true}, "invitation": {'s', true}, "request_hash": {'s', true}}
	payloadRequestSchema = map[string]payloadField{"version": {'i', true}, "app": {'s', true}, "group": {'s', true}, "invitation": {'s', true}, "member": {'m', true}, "token_hash": {'s', true}}
	payloadGrantSchema   = map[string]payloadField{"version": {'i', true}, "purpose": {'s', true}, "mode": {'s', true}, "app": {'s', true}, "group": {'s', true}, "invitation": {'s', true}, "expires": {'i', true}, "secret_hash": {'s', true}, "delegate_key": {'s', true}, "anchor_revision": {'i', true}, "anchor_hash": {'s', true}}
)

func payloadStrict(b []byte, schema map[string]payloadField) bool {
	if !utf8.Valid(b) {
		return false
	}
	p := &payloadScanner{b: b}
	return p.object(schema) && p.ws() == len(b)
}

type payloadScanner struct {
	b []byte
	i int
}

func (p *payloadScanner) ws() int {
	for p.i < len(p.b) && (p.b[p.i] == ' ' || p.b[p.i] == '\t' || p.b[p.i] == '\n' || p.b[p.i] == '\r') {
		p.i++
	}
	return p.i
}
func (p *payloadScanner) eat(c byte) bool {
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == c {
		p.i++
		return true
	}
	return false
}

// Keys are compared as raw bytes, so an escaped key never matches the schema.
func (p *payloadScanner) object(schema map[string]payloadField) bool {
	if !p.eat('{') {
		return false
	}
	seen := map[string]bool{}
	if !p.eat('}') {
		for {
			start := p.ws()
			if !p.str() {
				return false
			}
			k := string(p.b[start+1 : p.i-1])
			f, ok := schema[k]
			if !ok || seen[k] || !p.eat(':') || !p.value(f.kind) {
				return false
			}
			seen[k] = true
			if p.eat('}') {
				break
			}
			if !p.eat(',') {
				return false
			}
		}
	}
	for k, f := range schema {
		if f.required && !seen[k] {
			return false
		}
	}
	return true
}
func (p *payloadScanner) value(kind byte) bool {
	p.ws()
	switch kind {
	case 's':
		return p.str()
	case 'b':
		return p.word("true") || p.word("false")
	case 'i':
		return p.integer()
	case 'm':
		return p.object(payloadMemberSchema)
	case 'M':
		if !p.eat('[') {
			return false
		}
		if p.eat(']') {
			return true
		}
		for {
			if !p.object(payloadMemberSchema) {
				return false
			}
			if p.eat(']') {
				return true
			}
			if !p.eat(',') {
				return false
			}
		}
	}
	return false
}
func (p *payloadScanner) word(w string) bool {
	if bytes.HasPrefix(p.b[p.i:], []byte(w)) {
		p.i += len(w)
		return true
	}
	return false
}

// Only 0 or [1-9][0-9]* up to 2^53-1; a fraction or exponent fails at the caller.
func (p *payloadScanner) integer() bool {
	start := p.i
	for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
		p.i++
	}
	s := string(p.b[start:p.i])
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && (s == "0" || s[0] != '0') && n <= 1<<53-1
}
func (p *payloadScanner) str() bool {
	if p.i >= len(p.b) || p.b[p.i] != '"' {
		return false
	}
	for p.i++; p.i < len(p.b); p.i++ {
		switch c := p.b[p.i]; {
		case c == '"':
			p.i++
			return true
		case c < 0x20:
			return false
		case c == '\\':
			p.i++
			if p.i >= len(p.b) {
				return false
			}
			switch p.b[p.i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			case 'u':
				if p.i+4 >= len(p.b) {
					return false
				}
				for _, h := range p.b[p.i+1 : p.i+5] {
					if !((h >= '0' && h <= '9') || (h >= 'a' && h <= 'f') || (h >= 'A' && h <= 'F')) {
						return false
					}
				}
				n, err := strconv.ParseUint(string(p.b[p.i+1:p.i+5]), 16, 16)
				if err != nil || (n >= 0xd800 && n <= 0xdfff) {
					return false
				}
				p.i += 4
			default:
				return false
			}
		}
	}
	return false
}
