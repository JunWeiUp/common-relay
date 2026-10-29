//! Byte-level validation of signed group payloads.

/// The schema of a signed group payload.
#[derive(Clone, Copy)]
pub enum PayloadKind {
    State,
    Request,
    Grant,
}

const MEMBER: &[(&str, u8, bool)] = &[
    ("device", b's', true),
    ("name", b's', true),
    ("public_key", b's', true),
    ("signing_key", b's', true),
    ("manager", b'b', true),
];
const STATE: &[(&str, u8, bool)] = &[
    ("closed", b'b', false),
    ("name", b's', false),
    ("version", b'i', true),
    ("app", b's', true),
    ("group", b's', true),
    ("revision", b'i', true),
    ("previous", b's', true),
    ("members", b'M', true),
    ("invitation", b's', true),
    ("request_hash", b's', true),
];
const REQUEST: &[(&str, u8, bool)] = &[
    ("version", b'i', true),
    ("app", b's', true),
    ("group", b's', true),
    ("invitation", b's', true),
    ("member", b'm', true),
    ("token_hash", b's', true),
];
const GRANT: &[(&str, u8, bool)] = &[
    ("version", b'i', true),
    ("purpose", b's', true),
    ("mode", b's', true),
    ("app", b's', true),
    ("group", b's', true),
    ("invitation", b's', true),
    ("expires", b'i', true),
    ("secret_hash", b's', true),
    ("delegate_key", b's', true),
    ("anchor_revision", b'i', true),
    ("anchor_hash", b's', true),
];

/// Validate the exact JSON encoding accepted for signed group payloads.
pub fn validate_payload(raw: &[u8], kind: PayloadKind) -> bool {
    if std::str::from_utf8(raw).is_err() {
        return false;
    }
    let mut p = Scanner { b: raw, i: 0 };
    let schema = match kind {
        PayloadKind::State => STATE,
        PayloadKind::Request => REQUEST,
        PayloadKind::Grant => GRANT,
    };
    p.object(schema) && {
        p.ws();
        p.i == raw.len()
    }
}

struct Scanner<'a> {
    b: &'a [u8],
    i: usize,
}
impl Scanner<'_> {
    fn ws(&mut self) {
        while matches!(self.b.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn eat(&mut self, c: u8) -> bool {
        self.ws();
        if self.b.get(self.i) == Some(&c) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn object(&mut self, schema: &[(&str, u8, bool)]) -> bool {
        if !self.eat(b'{') {
            return false;
        }
        let mut seen = vec![false; schema.len()];
        if !self.eat(b'}') {
            loop {
                self.ws();
                let start = self.i;
                if !self.string() {
                    return false;
                }
                let key = &self.b[start + 1..self.i - 1];
                let Some(index) = schema.iter().position(|(k, _, _)| k.as_bytes() == key) else {
                    return false;
                };
                if seen[index] || !self.eat(b':') || !self.value(schema[index].1) {
                    return false;
                }
                seen[index] = true;
                if self.eat(b'}') {
                    break;
                }
                if !self.eat(b',') {
                    return false;
                }
            }
        }
        schema
            .iter()
            .enumerate()
            .all(|(i, (_, _, required))| !required || seen[i])
    }
    fn value(&mut self, kind: u8) -> bool {
        self.ws();
        match kind {
            b's' => self.string(),
            b'b' => self.word(b"true") || self.word(b"false"),
            b'i' => self.integer(),
            b'm' => self.object(MEMBER),
            b'M' => {
                if !self.eat(b'[') {
                    return false;
                }
                if self.eat(b']') {
                    return true;
                }
                loop {
                    if !self.object(MEMBER) {
                        return false;
                    }
                    if self.eat(b']') {
                        return true;
                    }
                    if !self.eat(b',') {
                        return false;
                    }
                }
            }
            _ => false,
        }
    }
    fn word(&mut self, word: &[u8]) -> bool {
        if self.b[self.i..].starts_with(word) {
            self.i += word.len();
            true
        } else {
            false
        }
    }
    fn integer(&mut self) -> bool {
        let start = self.i;
        while self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
            self.i += 1;
        }
        let s = &self.b[start..self.i];
        !s.is_empty()
            && (s == b"0" || s[0] != b'0')
            && std::str::from_utf8(s)
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .is_some_and(|n| n <= 9_007_199_254_740_991)
    }
    fn string(&mut self) -> bool {
        if self.b.get(self.i) != Some(&b'"') {
            return false;
        }
        self.i += 1;
        while let Some(&c) = self.b.get(self.i) {
            if c == b'"' {
                self.i += 1;
                return true;
            }
            if c < 0x20 {
                return false;
            }
            if c == b'\\' {
                self.i += 1;
                match self.b.get(self.i) {
                    Some(b'u') => {
                        let Some(h) = self.b.get(self.i + 1..self.i + 5) else {
                            return false;
                        };
                        if !h.iter().all(u8::is_ascii_hexdigit) {
                            return false;
                        }
                        let Ok(v) = u16::from_str_radix(std::str::from_utf8(h).unwrap_or(""), 16)
                        else {
                            return false;
                        };
                        if (0xd800..=0xdfff).contains(&v) {
                            return false;
                        }
                        self.i += 4;
                    }
                    Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {}
                    _ => return false,
                }
            }
            self.i += 1;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn strict_state_vectors() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../protocol/group-vectors.json")).unwrap();
        for (key, expected) in [("valid", true), ("invalid", false)] {
            for case in vectors["strict_payload"][key].as_array().unwrap() {
                let Ok(bytes) = STANDARD.decode(case["entry"]["payload"].as_str().unwrap()) else {
                    assert!(!expected);
                    continue;
                };
                assert_eq!(
                    validate_payload(&bytes, PayloadKind::State),
                    expected,
                    "{}",
                    case["case"]
                );
            }
        }
    }
    #[test]
    fn request_and_grant_are_strict() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../protocol/group-vectors.json")).unwrap();
        for (entry, kind) in [
            (&vectors["request"], PayloadKind::Request),
            (&vectors["auto_admission"]["grant"], PayloadKind::Grant),
        ] {
            let raw = STANDARD.decode(entry["payload"].as_str().unwrap()).unwrap();
            assert!(validate_payload(&raw, kind));
            let text = String::from_utf8(raw).unwrap();
            for bad in [
                text.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
                text.replacen("\"version\":1", "\"version\":1.0", 1),
                text.replacen("\"version\":1", "\"version\":null", 1),
                text.replacen("\"version\"", "\"VERSION\"", 1),
                text.replacen("\"version\"", "\"ver\\u0073ion\"", 1),
            ] {
                assert!(!validate_payload(bad.as_bytes(), kind));
            }
        }
    }
}
