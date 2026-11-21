//! Common Relay v2 client module for Rust (tailored for VaultApp).
//!
//! Covers:
//!   - `Box(object)` opaque client-encrypted sync with `If-Match` CAS optimistic locking
//!   - `Box(queue)` / `Box(ephemeral)` item upload, cursor listing, download & ACK
//!   - `/v2/ws` `PipeEvent` envelope + `[16B stream_id][chunk]` binary stream framing
//!   - Shared SHA-256 secret hashing (`hash_secret`)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxItem {
    pub id: String,
    pub space_id: String,
    pub box_name: String,
    pub seq: i64,
    pub sender: String,
    pub size: i64,
    pub sha256: String,
    pub content_type: String,
    pub meta_json: String,
    pub expires_at: i64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoxObject {
    pub space_id: String,
    pub box_name: String,
    pub key: String,
    pub version: i64,
    pub etag: String,
    pub size: i64,
    pub content_type: String,
    pub meta_json: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipeEvent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#box: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// Lowercase 64-char hex SHA-256 of a plaintext secret (matches protocol/v2/vectors.json).
pub fn hash_secret(plain: &str) -> String {
    let mut h = Sha256::new();
    h.update(plain.as_bytes());
    hex::encode(h.finalize())
}

/// Encodes a v2 `/v2/ws` binary stream frame: `[16-byte stream_id][payload]`.
pub fn encode_stream_frame(stream_id: &str, payload: &[u8]) -> Result<Vec<u8>, crate::Error> {
    if stream_id.len() != 16 {
        return Err(crate::Error::Invalid("stream_id must be exactly 16 bytes"));
    }
    let mut out = Vec::with_capacity(16 + payload.len());
    out.extend_from_slice(stream_id.as_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Decodes a v2 `/v2/ws` binary stream frame into `(stream_id, payload)`.
pub fn decode_stream_frame(frame: &[u8]) -> Result<(&str, &[u8]), crate::Error> {
    if frame.len() < 16 {
        return Err(crate::Error::Protocol("short binary stream frame"));
    }
    let sid = std::str::from_utf8(&frame[..16])
        .map_err(|_| crate::Error::Protocol("invalid stream_id utf-8"))?;
    Ok((sid, &frame[16..]))
}

#[derive(Debug, Clone)]
pub struct V2Client {
    base_url: String,
    access_password: String,
    token: String,
    http: reqwest::Client,
}

impl V2Client {
    pub fn new(
        base_url: impl Into<String>,
        access_password: impl Into<String>,
        token: impl Into<String>,
        allow_local: bool,
    ) -> Result<Self, crate::Error> {
        let base = base_url.into().trim_end_matches('/').to_string();
        let parsed = url::Url::parse(&base).map_err(|_| crate::Error::Invalid("invalid v2 URL"))?;
        match parsed.scheme() {
            "https" => {}
            "http" if allow_local => {
                let host = parsed.host_str().unwrap_or("");
                if host != "127.0.0.1" && host != "localhost" && host != "::1" {
                    return Err(crate::Error::Invalid("plain http only allowed on loopback"));
                }
            }
            _ => return Err(crate::Error::Invalid("v2 client requires https")),
        }
        Ok(Self {
            base_url: base,
            access_password: access_password.into(),
            token: token.into(),
            http: reqwest::Client::new(),
        })
    }

    pub fn ws_url(&self) -> String {
        if let Some(rest) = self.base_url.strip_prefix("https://") {
            format!("wss://{rest}/v2/ws")
        } else {
            format!(
                "ws://{}/v2/ws",
                self.base_url.trim_start_matches("http://")
            )
        }
    }

    fn apply_auth(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let rb = if !self.access_password.is_empty() {
            rb.header("Relay-Access", &self.access_password)
        } else {
            rb
        };
        rb.header("Authorization", format!("Bearer {}", self.token))
    }

    /// Uploads opaque ciphertext into `Box(object)` with optional `If-Match` CAS (`"none"` or ETag).
    /// Returns `Error::Http(409)` on CAS conflict so VaultApp can merge before retrying.
    pub async fn put_object(
        &self,
        space: &str,
        box_name: &str,
        key: &str,
        ciphertext: Vec<u8>,
        if_match: Option<&str>,
    ) -> Result<BoxObject, crate::Error> {
        let url = format!(
            "{}/v2/spaces/{}/boxes/{}/objects/{}",
            self.base_url,
            space,
            box_name,
            key.trim_start_matches('/')
        );
        let mut rb = self
            .apply_auth(self.http.put(url))
            .header("Content-Type", "application/octet-stream")
            .body(ciphertext);
        if let Some(m) = if_match {
            rb = rb.header("If-Match", m);
        }
        let resp = rb.send().await.map_err(|_| crate::Error::Connection("v2 put_object failed"))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(crate::Error::Http(status));
        }
        #[derive(Deserialize)]
        struct Res {
            object: BoxObject,
        }
        let parsed: Res = resp.json().await.map_err(|_| crate::Error::Protocol("invalid object json"))?;
        Ok(parsed.object)
    }

    /// Fetches opaque ciphertext bytes along with `(etag, version)`.
    pub async fn get_object(
        &self,
        space: &str,
        box_name: &str,
        key: &str,
    ) -> Result<(Vec<u8>, String, i64), crate::Error> {
        let url = format!(
            "{}/v2/spaces/{}/boxes/{}/objects/{}",
            self.base_url,
            space,
            box_name,
            key.trim_start_matches('/')
        );
        let resp = self
            .apply_auth(self.http.get(url))
            .send()
            .await
            .map_err(|_| crate::Error::Connection("v2 get_object failed"))?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(crate::Error::Http(status));
        }
        let etag = resp
            .headers()
            .get("ETag")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim_matches('"')
            .to_string();
        let ver = resp
            .headers()
            .get("X-Object-Version")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let bytes = resp
            .bytes()
            .await
            .map_err(|_| crate::Error::Connection("read object body failed"))?
            .to_vec();
        Ok((bytes, etag, ver))
    }

    pub async fn list_objects(
        &self,
        space: &str,
        box_name: &str,
    ) -> Result<Vec<BoxObject>, crate::Error> {
        let url = format!("{}/v2/spaces/{}/boxes/{}/objects", self.base_url, space, box_name);
        let resp = self
            .apply_auth(self.http.get(url))
            .send()
            .await
            .map_err(|_| crate::Error::Connection("v2 list_objects failed"))?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(crate::Error::Http(status));
        }
        #[derive(Deserialize)]
        struct Res {
            objects: Vec<BoxObject>,
        }
        let parsed: Res = resp.json().await.map_err(|_| crate::Error::Protocol("invalid objects json"))?;
        Ok(parsed.objects)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_protocol_v2_vectors() {
        assert_eq!(
            hash_secret("common-relay-v2-vector-secret"),
            "adc39f9ca5ad73f3c7e6aa2af6008c4e86e09e0d0c3596226b6b44ea82b20413"
        );
        let frame = encode_stream_frame("0123456789abcdef", b"ZIP_STREAM_CHUNK_DATA").unwrap();
        assert_eq!(
            hex::encode(&frame),
            "303132333435363738396162636465665a49505f53545245414d5f4348554e4b5f44415441"
        );
        let (sid, payload) = decode_stream_frame(&frame).unwrap();
        assert_eq!(sid, "0123456789abcdef");
        assert_eq!(payload, b"ZIP_STREAM_CHUNK_DATA");

        let c = V2Client::new("https://relay.example/", "acc", "tok", false).unwrap();
        assert_eq!(c.ws_url(), "wss://relay.example/v2/ws");
        assert!(V2Client::new("http://relay.example", "acc", "tok", false).is_err());
    }
}
