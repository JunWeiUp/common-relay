"""Strict signed-payload scan shared byte for byte with the relay and other SDKs.

JSON parsers disagree on duplicate keys, key case, unknown fields, null,
number forms and lone surrogates; a signed group record must have exactly one
reading everywhere (protocol/README.md, "严格载荷").
"""
MEMBER = {'device': ('s', True), 'name': ('s', True), 'public_key': ('s', True), 'signing_key': ('s', True), 'manager': ('b', True)}
STATE = {'closed': ('b', False), 'name': ('s', False), 'version': ('i', True), 'app': ('s', True), 'group': ('s', True), 'revision': ('i', True), 'previous': ('s', True), 'members': ('M', True), 'invitation': ('s', True), 'request_hash': ('s', True)}
REQUEST = {'version': ('i', True), 'app': ('s', True), 'group': ('s', True), 'invitation': ('s', True), 'member': ('m', True), 'token_hash': ('s', True)}
GRANT = {'version': ('i', True), 'purpose': ('s', True), 'mode': ('s', True), 'app': ('s', True), 'group': ('s', True), 'invitation': ('s', True), 'expires': ('i', True), 'secret_hash': ('s', True), 'delegate_key': ('s', True), 'anchor_revision': ('i', True), 'anchor_hash': ('s', True)}
SCHEMAS = (STATE, REQUEST, GRANT)
HEX = b'0123456789abcdefABCDEF'

class _Scanner:
    def __init__(self, b): self.b = b; self.i = 0
    def ws(self):
        while self.i < len(self.b) and self.b[self.i] in b' \t\n\r': self.i += 1
        return self.i
    def eat(self, c):
        self.ws()
        if self.b[self.i:self.i + 1] == c: self.i += 1; return True
        return False
    # Keys are compared as raw bytes, so an escaped key never matches the schema.
    def object(self, schema):
        if not self.eat(b'{'): return False
        seen = set()
        if not self.eat(b'}'):
            while True:
                start = self.ws()
                if not self.string(): return False
                k = self.b[start + 1:self.i - 1].decode()
                if k not in schema or k in seen or not self.eat(b':') or not self.value(schema[k][0]): return False
                seen.add(k)
                if self.eat(b'}'): break
                if not self.eat(b','): return False
        return all(k in seen for k, (_, required) in schema.items() if required)
    def value(self, kind):
        self.ws()
        if kind == 's': return self.string()
        if kind == 'b': return self.word(b'true') or self.word(b'false')
        if kind == 'i': return self.integer()
        if kind == 'm': return self.object(MEMBER)
        if not self.eat(b'['): return False
        if self.eat(b']'): return True
        while True:
            if not self.object(MEMBER): return False
            if self.eat(b']'): return True
            if not self.eat(b','): return False
    def word(self, w):
        if self.b.startswith(w, self.i): self.i += len(w); return True
        return False
    # Only 0 or [1-9][0-9]* up to 2^53-1; a fraction or exponent fails at the caller.
    def integer(self):
        start = self.i
        while self.i < len(self.b) and 48 <= self.b[self.i] <= 57: self.i += 1
        s = self.b[start:self.i]
        return bool(s) and (s == b'0' or s[:1] != b'0') and int(s) <= 2**53 - 1
    def string(self):
        if self.b[self.i:self.i + 1] != b'"': return False
        self.i += 1
        while self.i < len(self.b):
            c = self.b[self.i]
            if c == 0x22: self.i += 1; return True
            if c < 0x20: return False
            if c == 0x5c:
                self.i += 1
                e = self.b[self.i:self.i + 1]
                if e == b'u':
                    h = self.b[self.i + 1:self.i + 5]
                    if len(h) != 4 or any(x not in HEX for x in h) or 0xd800 <= int(h, 16) <= 0xdfff: return False
                    self.i += 4
                elif not e or e not in b'"\\/bfnrt': return False
            self.i += 1
        return False

def strict(raw, schema):
    try: raw.decode('utf-8')
    except UnicodeDecodeError: return False
    p = _Scanner(raw)
    return p.object(schema) and p.ws() == len(raw)
