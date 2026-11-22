//! Encrypted compact invitation links (`common-relay://host/v2/i/<id>#<key>`).
use crate::{Error, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use crypto_secretbox::{
    aead::{Aead, KeyInit},
    Nonce, XSalsa20Poly1305,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn invalid() -> Error {
    Error::Invalid("invalid compact invitation")
}
pub fn read_token(key: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(b"common-relay/invitation-link/read/v1\0");
    h.update(key);
    hex::encode(h.finalize())
}
pub fn seal(inv: &Value, key: &[u8; 32], nonce: &[u8; 24]) -> Result<String> {
    let plaintext = serde_json::to_vec(
        &json!({"version":1,"purpose":"common-relay/invitation-link/v1","invitation":inv}),
    )
    .map_err(|_| invalid())?;
    let cipher = XSalsa20Poly1305::new(key.into());
    let encrypted = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext.as_ref())
        .map_err(|_| invalid())?;
    let mut packet = nonce.to_vec();
    packet.extend(encrypted);
    Ok(STANDARD.encode(packet))
}
pub fn open_packet(packet: &str, key: &[u8; 32]) -> Result<Value> {
    let b = STANDARD.decode(packet).map_err(|_| invalid())?;
    if !(40..=16384).contains(&b.len()) {
        return Err(invalid());
    }
    let cipher = XSalsa20Poly1305::new(key.into());
    let plain = cipher
        .decrypt(Nonce::from_slice(&b[..24]), &b[24..])
        .map_err(|_| invalid())?;
    let v: Value = serde_json::from_slice(&plain).map_err(|_| invalid())?;
    if v["version"] != 1 || v["purpose"] != "common-relay/invitation-link/v1" {
        return Err(invalid());
    }
    v.get("invitation").cloned().ok_or_else(invalid)
}
/// `password` (optional server access password) is appended to the fragment as
/// `.<base64url>`; the fragment never reaches HTTP.
pub fn make_link(inv: &Value, key: &[u8; 32], password: Option<&str>) -> Result<String> {
    let suffix = match crate::access::checked_access_password(password)? {
        Some(p) => format!(".{}", URL_SAFE_NO_PAD.encode(p)),
        None => String::new(),
    };
    let u = url::Url::parse(inv["url"].as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    let id = hex::decode(inv["id"].as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    if id.len() != 16 {
        return Err(invalid());
    }
    let authority = &u[url::Position::BeforeHost..url::Position::AfterPort];
    Ok(format!(
        "common-relay://{authority}/v2/i/{}#{}{suffix}",
        URL_SAFE_NO_PAD.encode(id),
        URL_SAFE_NO_PAD.encode(key)
    ))
}
/// Returns `(relay url, invitation id, link key, optional access password)`.
pub fn parse_link(text: &str, local: bool) -> Result<(String, String, [u8; 32], Option<String>)> {
    if text.len() > 2048 {
        return Err(invalid());
    }
    let u = url::Url::parse(text).map_err(|_| invalid())?;
    if u.scheme() != "common-relay"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
    {
        return Err(invalid());
    }
    let id = u.path().strip_prefix("/v2/i/").ok_or_else(invalid)?;
    let fragment = u.fragment().ok_or_else(invalid)?;
    let (key, password) = match fragment.split_once('.') {
        Some((k, p)) => (k, Some(p)),
        None => (fragment, None),
    };
    let decode = |s: &str, n: usize| -> Result<Vec<u8>> {
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(invalid());
        }
        let b = URL_SAFE_NO_PAD.decode(s).map_err(|_| invalid())?;
        if b.len() != n || URL_SAFE_NO_PAD.encode(&b) != s {
            return Err(invalid());
        }
        Ok(b)
    };
    let id = hex::encode(decode(id, 16)?);
    let key = decode(key, 32)?.try_into().map_err(|_| invalid())?;
    let password = match password {
        None => None,
        Some(p) => {
            if p.is_empty()
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(invalid());
            }
            let raw = URL_SAFE_NO_PAD.decode(p).map_err(|_| invalid())?;
            if URL_SAFE_NO_PAD.encode(&raw) != p {
                return Err(invalid());
            }
            let text = String::from_utf8(raw).map_err(|_| invalid())?;
            if !crate::access::valid_access_password(&text) {
                return Err(invalid());
            }
            Some(text)
        }
    };
    let scheme = if local && u.host_str() == Some("127.0.0.1") {
        "ws"
    } else {
        "wss"
    };
    let authority = &u[url::Position::BeforeHost..url::Position::AfterPort];
    Ok((format!("{scheme}://{authority}/v2/ws"), id, key, password))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vectors() -> Value {
        serde_json::from_str(include_str!(
            "../../../protocol/v2/invitation-link-vectors.json"
        ))
        .unwrap()
    }
    fn key_nonce(v: &Value) -> ([u8; 32], [u8; 24]) {
        let key = hex::decode(v["key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let nonce = hex::decode(v["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        (key, nonce)
    }
    #[test]
    fn vectors_round_trip() {
        let v = vectors();
        let (key, nonce) = key_nonce(&v);
        let read = read_token(&key);
        assert_eq!(read, v["read_token"]);
        assert_eq!(
            hex::encode(Sha256::digest(read.as_bytes())),
            v["read_hash"].as_str().unwrap()
        );
        let packet = v["packet"].as_str().unwrap();
        assert_eq!(seal(&v["invitation"], &key, &nonce).unwrap(), packet);
        assert_eq!(open_packet(packet, &key).unwrap(), v["invitation"]);
        let raw = STANDARD.decode(packet).unwrap();
        let plain = XSalsa20Poly1305::new((&key).into())
            .decrypt(Nonce::from_slice(&raw[..24]), &raw[24..])
            .unwrap();
        assert_eq!(&raw[..24], &nonce);
        assert_eq!(plain, v["packet_plaintext"].as_str().unwrap().as_bytes());

        let link = v["link"].as_str().unwrap();
        assert_eq!(link.len() as u64, v["link_length"].as_u64().unwrap());
        assert_eq!(make_link(&v["invitation"], &key, None).unwrap(), link);
        let (url, id, k, p) = parse_link(link, false).unwrap();
        assert_eq!(url, v["invitation"]["url"]);
        assert_eq!(id, v["invitation"]["id"]);
        assert_eq!(k, key);
        assert_eq!(p, None);
        let pw = v["access_password"].as_str().unwrap();
        assert_eq!(
            make_link(&v["invitation"], &key, Some(pw)).unwrap(),
            v["link_with_password"]
        );
        let (url, id, k, p) = parse_link(v["link_with_password"].as_str().unwrap(), false).unwrap();
        assert_eq!(url, v["invitation"]["url"]);
        assert_eq!(id, v["invitation"]["id"]);
        assert_eq!(k, key);
        assert_eq!(p.as_deref(), Some(pw));
        assert!(make_link(&v["invitation"], &key, Some("short")).is_err());
    }
    #[test]
    fn rejects_bad_links_and_packets() {
        let v = vectors();
        let (key, _) = key_nonce(&v);
        let link = v["link"].as_str().unwrap();
        let invalid = v["invalid_links"].as_array().unwrap();
        assert!(!invalid.is_empty());
        for bad in invalid {
            let bad = bad.as_str().unwrap();
            assert!(parse_link(bad, false).is_err(), "accepted {bad}");
        }
        for bad in [
            link.replace("common-relay://", "https://"),
            link.replace("#", "?x=1#"),
        ] {
            assert!(parse_link(&bad, false).is_err(), "accepted {bad}");
        }
        let suffixes = v["invalid_link_suffixes"].as_array().unwrap();
        assert!(!suffixes.is_empty());
        for suffix in suffixes {
            let bad = format!("{link}{}", suffix.as_str().unwrap());
            assert!(parse_link(&bad, false).is_err(), "accepted {bad}");
        }
        let mut raw = STANDARD.decode(v["packet"].as_str().unwrap()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(open_packet(&STANDARD.encode(raw), &key).is_err());
        assert!(open_packet(v["packet"].as_str().unwrap(), &[0; 32]).is_err());
    }
}
