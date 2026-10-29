//! Encrypted compact invitation links.
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
pub fn make_link(inv: &Value, key: &[u8; 32]) -> Result<String> {
    let u = url::Url::parse(inv["url"].as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    let id = hex::decode(inv["id"].as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    if id.len() != 16 {
        return Err(invalid());
    }
    let authority = &u[url::Position::BeforeHost..url::Position::AfterPort];
    Ok(format!(
        "common-relay://{authority}/i/{}#{}",
        URL_SAFE_NO_PAD.encode(id),
        URL_SAFE_NO_PAD.encode(key)
    ))
}
pub fn parse_link(text: &str, local: bool) -> Result<(String, String, [u8; 32])> {
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
    let id = u.path().strip_prefix("/i/").ok_or_else(invalid)?;
    let key = u.fragment().ok_or_else(invalid)?;
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
    let scheme = if local && u.host_str() == Some("127.0.0.1") {
        "ws"
    } else {
        "wss"
    };
    let authority = &u[url::Position::BeforeHost..url::Position::AfterPort];
    Ok((format!("{scheme}://{authority}/relay/v1/ws"), id, key))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vectors() {
        let v: Value = serde_json::from_str(include_str!(
            "../../../protocol/invitation-link-vectors.json"
        ))
        .unwrap();
        let key: [u8; 32] = hex::decode(v["key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let nonce: [u8; 24] = hex::decode(v["nonce"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(read_token(&key), v["read_token"]);
        assert_eq!(seal(&v["invitation"], &key, &nonce).unwrap(), v["packet"]);
        assert_eq!(
            open_packet(v["packet"].as_str().unwrap(), &key).unwrap(),
            v["invitation"]
        );
        assert_eq!(make_link(&v["invitation"], &key).unwrap(), v["link"]);
        let (url, id, k) = parse_link(v["link"].as_str().unwrap(), false).unwrap();
        assert_eq!(url, v["invitation"]["url"]);
        assert_eq!(id, v["invitation"]["id"]);
        assert_eq!(k, key);
    }
    #[test]
    fn rejects_bad_links_and_packets() {
        let v: Value = serde_json::from_str(include_str!(
            "../../../protocol/invitation-link-vectors.json"
        ))
        .unwrap();
        let key: [u8; 32] = hex::decode(v["key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let link = v["link"].as_str().unwrap();
        for bad in [
            link.replace("common-relay://", "https://"),
            format!("{link}="),
            link.replace("/i/", "/j/"),
            link.replace("#", "?x=1#"),
        ] {
            assert!(parse_link(&bad, false).is_err());
        }
        let mut raw = STANDARD.decode(v["packet"].as_str().unwrap()).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(open_packet(&STANDARD.encode(raw), &key).is_err());
        assert!(open_packet(v["packet"].as_str().unwrap(), &[0; 32]).is_err());
    }
}
