package relay

import (
	"bytes"
	"encoding/json"
	"strconv"
	"unicode/utf8"
)

// Signed payloads are re-verified by four SDKs whose JSON parsers disagree on
// duplicate keys, key case, unknown fields, null, number forms and lone
// surrogates. Accept one unambiguous shape only, so the relay never stores a
// record that a client reads differently or cannot read at all. The SDKs run
// the same byte-level scan (protocol/README.md, "严格载荷").
type field struct {
	kind     byte // s string, i safe integer, b bool, m member, M member list
	required bool
}

var (
	memberSchema  = map[string]field{"device": {'s', true}, "name": {'s', true}, "public_key": {'s', true}, "signing_key": {'s', true}, "manager": {'b', true}}
	stateSchema   = map[string]field{"closed": {'b', false}, "name": {'s', false}, "version": {'i', true}, "app": {'s', true}, "group": {'s', true}, "revision": {'i', true}, "previous": {'s', true}, "members": {'M', true}, "invitation": {'s', true}, "request_hash": {'s', true}}
	requestSchema = map[string]field{"version": {'i', true}, "app": {'s', true}, "group": {'s', true}, "invitation": {'s', true}, "member": {'m', true}, "token_hash": {'s', true}}
	grantSchema   = map[string]field{"version": {'i', true}, "purpose": {'s', true}, "mode": {'s', true}, "app": {'s', true}, "group": {'s', true}, "invitation": {'s', true}, "expires": {'i', true}, "secret_hash": {'s', true}, "delegate_key": {'s', true}, "anchor_revision": {'i', true}, "anchor_hash": {'s', true}}
)

func decodeStrict(b []byte, schema map[string]field, v any) error {
	if !strictPayload(b, schema) {
		return ErrDenied
	}
	return json.Unmarshal(b, v)
}
func strictPayload(b []byte, schema map[string]field) bool {
	if !utf8.Valid(b) {
		return false
	}
	p := &scanner{b: b}
	return p.object(schema) && p.ws() == len(b)
}

type scanner struct {
	b []byte
	i int
}

func (p *scanner) ws() int {
	for p.i < len(p.b) && (p.b[p.i] == ' ' || p.b[p.i] == '\t' || p.b[p.i] == '\n' || p.b[p.i] == '\r') {
		p.i++
	}
	return p.i
}
func (p *scanner) eat(c byte) bool {
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == c {
		p.i++
		return true
	}
	return false
}

// Keys are compared as raw bytes, so an escaped key never matches the schema.
func (p *scanner) object(schema map[string]field) bool {
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
func (p *scanner) value(kind byte) bool {
	p.ws()
	switch kind {
	case 's':
		return p.str()
	case 'b':
		return p.word("true") || p.word("false")
	case 'i':
		return p.integer()
	case 'm':
		return p.object(memberSchema)
	case 'M':
		if !p.eat('[') {
			return false
		}
		if p.eat(']') {
			return true
		}
		for {
			if !p.object(memberSchema) {
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
func (p *scanner) word(w string) bool {
	if bytes.HasPrefix(p.b[p.i:], []byte(w)) {
		p.i += len(w)
		return true
	}
	return false
}

// Only 0 or [1-9][0-9]* up to 2^53-1; a fraction or exponent fails at the caller.
func (p *scanner) integer() bool {
	start := p.i
	for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
		p.i++
	}
	s := string(p.b[start:p.i])
	n, err := strconv.ParseUint(s, 10, 64)
	return err == nil && (s == "0" || s[0] != '0') && n <= 1<<53-1
}
func (p *scanner) str() bool {
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
