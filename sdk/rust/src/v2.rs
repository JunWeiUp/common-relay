//! Common Relay v2 client module for Rust.
//!
//! Covers:
//!   - `Box(object)` opaque client-encrypted sync with `If-Match` CAS optimistic locking
//!   - `Box(queue)` / `Box(ephemeral)` item upload, cursor listing, download & ACK
//!   - `/v2/ws` `PipeEvent` envelope + `[16B stream_id][chunk]` binary stream framing
//!   - Shared SHA-256 secret hashing (`hash_secret`)
//!   - Admin plugin catalog / binding read / partial `PATCH` / scrypt account passwords
//!   - Opening `crs1` sealed bridge payloads (`open_sealed`, `generate_seal_key_pair`)

use crypto_secretbox::{
    aead::{Aead, KeyInit},
    Nonce, XSalsa20Poly1305,
};
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

/// Error from the v2 admin plugin API. `Api` keeps the response body so callers can
/// tell an old server (plain-text 404/405) from a JSON error of a new one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum V2Error {
    #[error("relay v2 http {status}: {message}")]
    Api { status: u16, message: String },
    #[error(transparent)]
    Client(#[from] crate::Error),
}

impl V2Error {
    /// True when the server predates the endpoint (see [`is_unsupported`]); callers can
    /// then fall back to the older PUT API.
    pub fn is_unsupported(&self) -> bool {
        match self {
            V2Error::Api { status, message } => is_unsupported(*status, message),
            V2Error::Client(_) => false,
        }
    }
}

/// Reports that a status/body pair comes from a server without the endpoint:
/// 405 or 501, or a 404 whose body is not a JSON error (new servers answer JSON).
pub fn is_unsupported(status: u16, body: &str) -> bool {
    status == 405 || status == 501 || (status == 404 && !body.trim().starts_with('{'))
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginBindingSummary {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_device: String,
    #[serde(default)]
    pub target_online: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub public_base: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tag: String,
    #[serde(default)]
    pub has_hmac: bool,
    #[serde(default)]
    pub has_token: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cors_origins: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginAccountView {
    pub scope_key: String,
    pub username: String,
    pub mode: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginBinding {
    pub id: String,
    pub plugin_id: String,
    pub mount: String,
    pub space_id: String,
    pub box_name: String,
    pub config_json: String,
    pub enabled: bool,
    pub updated_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<PluginBindingSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<PluginAccountView>,
    /// Increments on every change; pass it as `if_version` for optimistic concurrency.
    /// Zero on servers older than the PATCH API.
    pub config_version: i64,
    /// Write-only secret keys currently set (values are never returned).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub secret_keys: Vec<String>,
    /// Bridged payloads are sealed (`crs1`) to the binding's `seal_public_key`.
    pub sealed: bool,
}

/// One config key a plugin accepts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginFieldSpec {
    pub key: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default)]
    pub secret: bool,
    #[serde(default)]
    pub required: bool,
}

/// A registered plugin with its config schema (empty on servers without schemas).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginInfo {
    pub id: String,
    #[serde(default)]
    pub required_trust: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema: Vec<PluginFieldSpec>,
}

/// Partial binding update. `None` fields are unchanged; a `config` entry set to
/// `Value::Null` deletes that key. Secret keys are write-only: send a plaintext
/// `"token"` to rotate a Bearer token (hashed server-side). `if_version == 0` skips
/// the version check.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct PluginPatch {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub box_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "is_zero")]
    pub if_version: i64,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginAccount {
    pub binding_id: String,
    pub scope_key: String,
    pub username: String,
    pub mode: String,
    pub meta_json: String,
    pub updated_at: i64,
}

/// A registered v2 device (never includes the token).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub is_admin: bool,
    pub revoked: bool,
    pub created_at: i64,
}

/// Result of [`V2Client::me`]: the token's device, or `root_admin` (and no
/// device) for the Root Admin secret.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Me {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<Device>,
    pub root_admin: bool,
}

/// Percent-encodes one path segment (RFC 3986 unreserved characters pass through).
fn path_escape(seg: &str) -> String {
    let mut out = String::with_capacity(seg.len());
    for b in seg.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/* ───────── Sealed bridge payloads ("crs1") ───────── */

/// Scheme name stored in item meta `"sealed"`.
pub const SEALED_SCHEME: &str = "crs1";
/// Content type of queue items whose body is a `crs1` sealed payload; the original
/// content type is kept in item meta `"content_type"`.
pub const SEALED_CONTENT_TYPE: &str = "application/vnd.common-relay.sealed";
const SEALED_MAGIC: &[u8; 4] = b"CRS1";
const SEALED_CHUNK_SIZE: usize = 64 << 10;
const SECRETBOX_OVERHEAD: usize = 16;
const SEALED_KEY_LEN: usize = 32 + 48; // crypto_box_seal(32-byte key)
const SEALED_HEADER_LEN: usize = 4 + SEALED_KEY_LEN + 16;
const FINAL_FRAME_BIT: u64 = 1 << 63;

/// Decodes a 64-char hex X25519 key (public or private).
pub fn parse_public_key(hex_key: &str) -> Result<[u8; 32], crate::Error> {
    hex::decode(hex_key.trim())
        .ok()
        .and_then(|raw| <[u8; 32]>::try_from(raw).ok())
        .ok_or(crate::Error::Invalid(
            "public key must be 64 hex characters",
        ))
}

/// Creates a fresh X25519 key pair for sealed bridge payloads as `(public_hex, private_hex)`.
/// Configure the public half as the binding's `seal_public_key`.
pub fn generate_seal_key_pair() -> Result<(String, String), crate::Error> {
    let mut secret = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::getrandom(secret.as_mut())
        .map_err(|_| crate::Error::Crypto("random source failed"))?;
    let sk = crypto_box::SecretKey::from(*secret);
    Ok((
        hex::encode(sk.public_key().as_bytes()),
        hex::encode(secret.as_ref()),
    ))
}

/// Reports whether data starts with the sealed-payload magic.
pub fn is_sealed(head: &[u8]) -> bool {
    head.len() >= 4 && &head[..4] == SEALED_MAGIC
}

fn frame_nonce(prefix: &[u8], ctr: u64) -> [u8; 24] {
    let mut n = [0u8; 24];
    n[..16].copy_from_slice(prefix);
    n[16..].copy_from_slice(&ctr.to_be_bytes());
    n
}

/// Decrypts a complete `crs1` sealed payload with the recipient key pair.
/// Fails on a wrong key, tampering, or truncation (the last frame must carry the final bit).
pub fn open_sealed(
    sealed: &[u8],
    public_key: &[u8; 32],
    secret_key: &[u8; 32],
) -> Result<Vec<u8>, crate::Error> {
    let corrupt = crate::Error::Crypto("sealed payload corrupt or truncated");
    if sealed.len() < SEALED_HEADER_LEN || !is_sealed(sealed) {
        return Err(corrupt);
    }
    let sk = crypto_box::SecretKey::from(*secret_key);
    if sk.public_key().as_bytes() != public_key {
        return Err(corrupt);
    }
    let raw_key = zeroize::Zeroizing::new(
        sk.unseal(&sealed[4..4 + SEALED_KEY_LEN])
            .map_err(|_| corrupt.clone())?,
    );
    if raw_key.len() != 32 {
        return Err(corrupt);
    }
    let cipher = XSalsa20Poly1305::new(raw_key.as_slice().into());
    let prefix = &sealed[4 + SEALED_KEY_LEN..SEALED_HEADER_LEN];
    let mut rest = &sealed[SEALED_HEADER_LEN..];
    let mut out = Vec::new();
    let mut ctr: u64 = 0;
    loop {
        if rest.len() < 4 {
            return Err(corrupt);
        }
        let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
        rest = &rest[4..];
        if !(SECRETBOX_OVERHEAD..=SEALED_CHUNK_SIZE + SECRETBOX_OVERHEAD).contains(&len)
            || len > rest.len()
        {
            return Err(corrupt);
        }
        let (frame, tail) = rest.split_at(len);
        rest = tail;
        let last = rest.is_empty();
        let nonce = frame_nonce(prefix, if last { ctr | FINAL_FRAME_BIT } else { ctr });
        let plain = cipher
            .decrypt(Nonce::from_slice(&nonce), frame)
            .map_err(|_| corrupt.clone())?;
        out.extend_from_slice(&plain);
        if last {
            return Ok(out);
        }
        ctr += 1;
    }
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
            format!("ws://{}/v2/ws", self.base_url.trim_start_matches("http://"))
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

    fn uploads_url(&self, space: &str, box_name: &str, suffix: &str) -> String {
        format!("{}/v2/spaces/{space}/boxes/{box_name}/uploads{suffix}", self.base_url)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_box_upload(
        &self,
        space: &str,
        box_name: &str,
        total_size: u64,
        key: &str,
        content_type: &str,
        meta_json: &str,
        ttl_sec: u64,
    ) -> Result<serde_json::Value, crate::Error> {
        let mut body = serde_json::json!({
            "total_size": total_size,
            "content_type": if content_type.is_empty() { "application/octet-stream" } else { content_type },
            "meta": if meta_json.is_empty() { "{}" } else { meta_json },
        });
        if !key.is_empty() {
            body["key"] = serde_json::Value::String(key.to_string());
        }
        if ttl_sec > 0 {
            body["ttl"] = serde_json::json!(ttl_sec);
        }
        let resp = self
            .apply_auth(self.http.post(self.uploads_url(space, box_name, "")))
            .json(&body)
            .send()
            .await
            .map_err(|_| crate::Error::Connection("box upload create failed"))?;
        if !resp.status().is_success() {
            return Err(crate::Error::Http(resp.status().as_u16()));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|_| crate::Error::Protocol("invalid box upload json"))?;
        Ok(v["upload"].clone())
    }

    pub async fn get_box_upload(
        &self,
        space: &str,
        box_name: &str,
        upload_id: &str,
    ) -> Result<serde_json::Value, crate::Error> {
        let resp = self
            .apply_auth(self.http.get(self.uploads_url(space, box_name, &format!("/{upload_id}"))))
            .send()
            .await
            .map_err(|_| crate::Error::Connection("box upload get failed"))?;
        if !resp.status().is_success() {
            return Err(crate::Error::Http(resp.status().as_u16()));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|_| crate::Error::Protocol("invalid box upload json"))?;
        Ok(v["upload"].clone())
    }

    pub async fn append_box_upload_chunk(
        &self,
        space: &str,
        box_name: &str,
        upload_id: &str,
        offset: u64,
        chunk: Vec<u8>,
    ) -> Result<serde_json::Value, crate::Error> {
        let url = self.uploads_url(space, box_name, &format!("/{upload_id}?offset={offset}"));
        let resp = self
            .apply_auth(self.http.patch(url))
            .header("Content-Type", "application/octet-stream")
            .body(chunk)
            .send()
            .await
            .map_err(|_| crate::Error::Connection("box upload chunk failed"))?;
        if !resp.status().is_success() {
            return Err(crate::Error::Http(resp.status().as_u16()));
        }
        let v: serde_json::Value = resp
            .json()
            .await
            .map_err(|_| crate::Error::Protocol("invalid box upload json"))?;
        Ok(v["upload"].clone())
    }

    pub async fn complete_box_upload(
        &self,
        space: &str,
        box_name: &str,
        upload_id: &str,
        sha256_hex: &str,
        expected_etag: &str,
    ) -> Result<serde_json::Value, crate::Error> {
        let mut body = serde_json::Map::new();
        if !sha256_hex.is_empty() {
            body.insert("sha256".into(), serde_json::Value::String(sha256_hex.into()));
        }
        if !expected_etag.is_empty() {
            body.insert("expected_etag".into(), serde_json::Value::String(expected_etag.into()));
        }
        let url = self.uploads_url(space, box_name, &format!("/{upload_id}/complete"));
        let resp = self
            .apply_auth(self.http.post(url))
            .json(&serde_json::Value::Object(body))
            .send()
            .await
            .map_err(|_| crate::Error::Connection("box upload complete failed"))?;
        if !resp.status().is_success() {
            return Err(crate::Error::Http(resp.status().as_u16()));
        }
        resp.json()
            .await
            .map_err(|_| crate::Error::Protocol("invalid box upload complete json"))
    }

    pub async fn abort_box_upload(
        &self,
        space: &str,
        box_name: &str,
        upload_id: &str,
    ) -> Result<(), crate::Error> {
        let url = self.uploads_url(space, box_name, &format!("/{upload_id}"));
        let resp = self
            .apply_auth(self.http.delete(url))
            .send()
            .await
            .map_err(|_| crate::Error::Connection("box upload abort failed"))?;
        if !resp.status().is_success() {
            return Err(crate::Error::Http(resp.status().as_u16()));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upload_box_resumable(
        &self,
        space: &str,
        box_name: &str,
        data: &[u8],
        key: &str,
        content_type: &str,
        meta_json: &str,
        chunk_size: usize,
        ttl_sec: u64,
        expected_etag: &str,
    ) -> Result<serde_json::Value, crate::Error> {
        let step = if chunk_size == 0 { 256 * 1024 } else { chunk_size };
        let digest = hex::encode(Sha256::digest(data));
        let mut up = self
            .create_box_upload(space, box_name, data.len() as u64, key, content_type, meta_json, ttl_sec)
            .await?;
        let uid = up["id"]
            .as_str()
            .ok_or(crate::Error::Protocol("missing upload id"))?
            .to_string();
        let mut offset = 0usize;
        while offset < data.len() {
            let end = (offset + step).min(data.len());
            up = self
                .append_box_upload_chunk(space, box_name, &uid, offset as u64, data[offset..end].to_vec())
                .await?;
            offset = up["offset"].as_u64().unwrap_or(end as u64) as usize;
        }
        self.complete_box_upload(space, box_name, &uid, &digest, expected_etag)
            .await
    }

    /// Uploads opaque ciphertext into `Box(object)` with optional `If-Match` CAS (`"none"` or ETag).
    /// Returns `Error::Http(409)` on CAS conflict so callers can merge before retrying.
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
        let resp = rb
            .send()
            .await
            .map_err(|_| crate::Error::Connection("v2 put_object failed"))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(crate::Error::Http(status));
        }
        #[derive(Deserialize)]
        struct Res {
            object: BoxObject,
        }
        let parsed: Res = resp
            .json()
            .await
            .map_err(|_| crate::Error::Protocol("invalid object json"))?;
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
        let url = format!(
            "{}/v2/spaces/{}/boxes/{}/objects",
            self.base_url, space, box_name
        );
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
        let parsed: Res = resp
            .json()
            .await
            .map_err(|_| crate::Error::Protocol("invalid objects json"))?;
        Ok(parsed.objects)
    }
    async fn admin_json<T: serde::de::DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, V2Error> {
        let mut rb = self.apply_auth(
            self.http
                .request(method, format!("{}{}", self.base_url, path)),
        );
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let resp = rb
            .send()
            .await
            .map_err(|_| crate::Error::Connection("v2 admin request failed"))?;
        let status = resp.status().as_u16();
        if !(200..300).contains(&status) {
            let text = resp.text().await.unwrap_or_default();
            let mut message = text.trim().to_string();
            if message.len() > 4096 {
                let mut cut = 4096;
                while !message.is_char_boundary(cut) {
                    cut -= 1;
                }
                message.truncate(cut);
            }
            return Err(V2Error::Api { status, message });
        }
        Ok(resp
            .json()
            .await
            .map_err(|_| crate::Error::Protocol("invalid v2 admin json"))?)
    }

    fn plugin_path(plugin_id: &str, mount: &str) -> String {
        format!(
            "/v2/admin/plugins/{}/{}",
            path_escape(plugin_id),
            path_escape(mount)
        )
    }

    /// The device the client's token belongs to (`GET /v2/me`). `root_admin` is
    /// true (and `device` `None`) for the Root Admin secret. Older servers fail
    /// with [`V2Error::is_unsupported`].
    pub async fn me(&self) -> Result<Me, V2Error> {
        self.admin_json(reqwest::Method::GET, "/v2/me", None).await
    }

    /// Registered plugins with their config schemas (`GET /v2/admin/plugins`).
    pub async fn plugin_catalog(&self) -> Result<Vec<PluginInfo>, V2Error> {
        #[derive(Deserialize)]
        struct Res {
            #[serde(default)]
            plugins: Option<Vec<PluginInfo>>,
        }
        let res: Res = self
            .admin_json(reqwest::Method::GET, "/v2/admin/plugins", None)
            .await?;
        Ok(res.plugins.unwrap_or_default())
    }

    /// One binding (public view) regardless of its enabled state.
    pub async fn get_plugin(&self, plugin_id: &str, mount: &str) -> Result<PluginBinding, V2Error> {
        #[derive(Deserialize)]
        struct Res {
            binding: PluginBinding,
        }
        let res: Res = self
            .admin_json(
                reqwest::Method::GET,
                &Self::plugin_path(plugin_id, mount),
                None,
            )
            .await?;
        Ok(res.binding)
    }

    /// Merges a partial update into an existing binding (never creates one).
    /// Servers older than the PATCH API fail with [`V2Error::is_unsupported`].
    pub async fn patch_plugin(
        &self,
        plugin_id: &str,
        mount: &str,
        patch: &PluginPatch,
    ) -> Result<PluginBinding, V2Error> {
        #[derive(Deserialize)]
        struct Res {
            binding: PluginBinding,
        }
        let body = serde_json::to_value(patch)
            .map_err(|_| crate::Error::Invalid("invalid plugin patch"))?;
        let res: Res = self
            .admin_json(
                reqwest::Method::PATCH,
                &Self::plugin_path(plugin_id, mount),
                Some(body),
            )
            .await?;
        Ok(res.binding)
    }

    /// Stores an account whose password the server hashes with salted scrypt
    /// (preferred over the legacy bare `secret_sha256`).
    pub async fn upsert_plugin_account_password(
        &self,
        plugin_id: &str,
        mount: &str,
        scope_key: &str,
        username: &str,
        password: &str,
        mode: &str,
    ) -> Result<PluginAccount, V2Error> {
        #[derive(Deserialize)]
        struct Res {
            account: PluginAccount,
        }
        let body = serde_json::json!({
            "scope_key": scope_key, "username": username, "password": password, "mode": mode,
        });
        let res: Res = self
            .admin_json(
                reqwest::Method::PUT,
                &format!("{}/accounts", Self::plugin_path(plugin_id, mount)),
                Some(body),
            )
            .await?;
        Ok(res.account)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors(name: &str) -> serde_json::Value {
        let path = format!("{}/../../protocol/v2/{name}", env!("CARGO_MANIFEST_DIR"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn matches_protocol_v2_vectors() {
        let v = vectors("vectors.json");
        let cases = v["hash_secret"].as_array().unwrap();
        assert!(!cases.is_empty());
        for c in cases {
            assert_eq!(
                hash_secret(c["input"].as_str().unwrap()),
                c["sha256"].as_str().unwrap(),
                "{}",
                c["use"]
            );
        }
        let f = &v["binary_stream_frame"];
        let sid = f["stream_id"].as_str().unwrap();
        let payload = f["payload_utf8"].as_str().unwrap().as_bytes();
        let frame = encode_stream_frame(sid, payload).unwrap();
        assert_eq!(hex::encode(&frame), f["frame_hex"].as_str().unwrap());
        let wire = hex::decode(f["frame_hex"].as_str().unwrap()).unwrap();
        let (got_sid, got_payload) = decode_stream_frame(&wire).unwrap();
        assert_eq!(got_sid, sid);
        assert_eq!(got_payload, payload);

        let c = V2Client::new("https://relay.example/", "acc", "tok", false).unwrap();
        assert_eq!(c.ws_url(), "wss://relay.example/v2/ws");
        assert!(V2Client::new("http://relay.example", "acc", "tok", false).is_err());
    }

    #[test]
    fn opens_shared_sealed_vectors() {
        use base64::Engine;
        use sha2::Digest;
        let v = vectors("sealed-vectors.json");
        let key = |k: &str| parse_public_key(v[k].as_str().unwrap()).unwrap();
        let (public, secret) = (key("recipient_public"), key("recipient_private"));
        let mut sealed_by_name = std::collections::HashMap::new();
        let valid = v["valid"].as_array().unwrap();
        assert!(valid.len() >= 3);
        for c in valid {
            let name = c["name"].as_str().unwrap();
            let sealed = base64::engine::general_purpose::STANDARD
                .decode(c["sealed_b64"].as_str().unwrap())
                .unwrap();
            assert!(is_sealed(&sealed), "{name}");
            let plain = open_sealed(&sealed, &public, &secret).unwrap();
            assert_eq!(
                plain.len() as u64,
                c["plaintext_length"].as_u64().unwrap(),
                "{name}"
            );
            assert_eq!(
                hex::encode(sha2::Sha256::digest(&plain)),
                c["plaintext_sha256"].as_str().unwrap(),
                "{name}"
            );
            if let Some(h) = c["plaintext_hex"].as_str() {
                assert_eq!(hex::encode(&plain), h, "{name}");
            }
            if name == "two_frames" {
                let want: Vec<u8> = (0..plain.len())
                    .map(|i| ((i * 7 + 3) & 0xff) as u8)
                    .collect();
                assert_eq!(plain, want);
            }
            sealed_by_name.insert(name.to_string(), sealed);
        }
        assert!(!is_sealed(b"CRS"));

        let invalid = v["invalid"].as_array().unwrap();
        assert!(!invalid.is_empty());
        for c in invalid {
            let name = c["name"].as_str().unwrap();
            let mut bad = sealed_by_name[c["base"].as_str().unwrap()].clone();
            match c["op"].as_str().unwrap() {
                "truncate" => bad.truncate(c["length"].as_u64().unwrap() as usize),
                "append" => bad.extend(hex::decode(c["hex"].as_str().unwrap()).unwrap()),
                "flip" => bad[c["offset"].as_u64().unwrap() as usize] ^= 0x01,
                op => panic!("unknown op {op}"),
            }
            assert!(
                open_sealed(&bad, &public, &secret).is_err(),
                "accepted {name}"
            );
        }

        let hello = &sealed_by_name["hello"];
        let (wp, ws) = (key("wrong_public"), key("wrong_private"));
        assert!(open_sealed(hello, &wp, &ws).is_err());
        // Mismatched public/secret halves.
        assert!(open_sealed(hello, &wp, &secret).is_err());
        assert!(open_sealed(hello, &public, &ws).is_err());
    }

    #[test]
    fn generated_seal_key_pair_is_consistent() {
        let (pub_hex, priv_hex) = generate_seal_key_pair().unwrap();
        assert_eq!(pub_hex.len(), 64);
        assert_eq!(priv_hex.len(), 64);
        let secret = parse_public_key(&priv_hex).unwrap();
        let derived = crypto_box::SecretKey::from(secret).public_key();
        assert_eq!(hex::encode(derived.as_bytes()), pub_hex);
        assert!(parse_public_key("abcd").is_err());
        assert!(parse_public_key(&"zz".repeat(32)).is_err());
    }

    /// Builds a multi-frame crs1 payload with the same primitives (tests only).
    fn seal_for_test(recipient: &[u8; 32], plain: &[u8]) -> Vec<u8> {
        let key = [7u8; 32];
        let prefix = [9u8; 16];
        let pk = crypto_box::PublicKey::from(*recipient);
        let sealed_key = pk.seal(&mut crypto_box::aead::OsRng, &key).unwrap();
        let mut out = SEALED_MAGIC.to_vec();
        out.extend_from_slice(&sealed_key);
        out.extend_from_slice(&prefix);
        let cipher = XSalsa20Poly1305::new((&key).into());
        let chunks: Vec<&[u8]> = if plain.is_empty() {
            vec![&[]]
        } else {
            plain.chunks(SEALED_CHUNK_SIZE).collect()
        };
        for (i, chunk) in chunks.iter().enumerate() {
            let mut ctr = i as u64;
            if i == chunks.len() - 1 {
                ctr |= FINAL_FRAME_BIT;
            }
            let ct = cipher
                .encrypt(Nonce::from_slice(&frame_nonce(&prefix, ctr)), *chunk)
                .unwrap();
            out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
            out.extend_from_slice(&ct);
        }
        out
    }

    #[test]
    fn opens_multi_frame_and_detects_dropped_final_frame() {
        let (pub_hex, priv_hex) = generate_seal_key_pair().unwrap();
        let (public, secret) = (
            parse_public_key(&pub_hex).unwrap(),
            parse_public_key(&priv_hex).unwrap(),
        );
        let plain: Vec<u8> = (0..2 * SEALED_CHUNK_SIZE + 5)
            .map(|i| (i % 251) as u8)
            .collect();
        let sealed = seal_for_test(&public, &plain);
        assert_eq!(open_sealed(&sealed, &public, &secret).unwrap(), plain);
        let cut = &sealed[..sealed.len() - (4 + 5 + SECRETBOX_OVERHEAD)];
        assert!(open_sealed(cut, &public, &secret).is_err());
    }

    #[test]
    fn unsupported_detection() {
        assert!(is_unsupported(405, ""));
        assert!(is_unsupported(501, "{\"ok\":false}"));
        assert!(is_unsupported(404, "404 page not found"));
        assert!(!is_unsupported(
            404,
            "{\"ok\":false,\"error\":\"not found\"}"
        ));
        assert!(!is_unsupported(404, "  {\"ok\":false}"));
        assert!(!is_unsupported(409, "conflict"));
        assert!(V2Error::Api {
            status: 404,
            message: "404 page not found".into()
        }
        .is_unsupported());
        assert!(!V2Error::Client(crate::Error::Http(404)).is_unsupported());
    }

    #[test]
    fn decodes_binding_from_old_and_new_servers() {
        let old: PluginBinding = serde_json::from_str(
            r#"{"id":"b1","plugin_id":"drop","mount":"m","space_id":"s","box_name":"drop/m","config_json":"{}","enabled":true,"updated_at":5}"#,
        )
        .unwrap();
        assert_eq!(old.config_version, 0);
        assert!(old.secret_keys.is_empty() && !old.sealed && old.summary.is_none());
        let new: PluginBinding = serde_json::from_str(
            r#"{"id":"b1","plugin_id":"webhook","mount":"m","config_version":3,"secret_keys":["token_sha256"],"sealed":true,"summary":{"has_token":true},"accounts":[{"scope_key":"k","username":"u","mode":"rw"}]}"#,
        )
        .unwrap();
        assert_eq!(new.config_version, 3);
        assert_eq!(new.secret_keys, vec!["token_sha256"]);
        assert!(new.sealed && new.summary.unwrap().has_token);
        assert_eq!(new.accounts[0].username, "u");
    }

    struct Captured {
        method: String,
        path: String,
        headers: String,
        body: String,
    }

    /// One-shot HTTP/1.1 server: captures the request and answers `status` + `body`.
    async fn one_shot(
        status: &'static str,
        body: &'static str,
    ) -> (String, tokio::task::JoinHandle<Captured>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            let head_end = loop {
                let n = sock.read(&mut tmp).await.unwrap();
                buf.extend_from_slice(&tmp[..n]);
                if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let len = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while buf.len() < head_end + len {
                let n = sock.read(&mut tmp).await.unwrap();
                buf.extend_from_slice(&tmp[..n]);
            }
            let ctype = if body.starts_with('{') {
                "application/json"
            } else {
                "text/plain"
            };
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            let mut first = head.lines().next().unwrap().split(' ');
            Captured {
                method: first.next().unwrap().to_string(),
                path: first.next().unwrap().to_string(),
                headers: head.to_ascii_lowercase(),
                body: String::from_utf8_lossy(&buf[head_end..head_end + len]).to_string(),
            }
        });
        (base, handle)
    }

    const BINDING_JSON: &str = r#"{"ok":true,"binding":{"id":"b1","plugin_id":"web hook","mount":"m/1","config_version":4,"sealed":true}}"#;

    #[tokio::test]
    async fn patch_plugin_request_shape() {
        let (base, srv) = one_shot("200 OK", BINDING_JSON).await;
        let c = V2Client::new(base, "acc-password", "admintok", true).unwrap();
        let mut config = serde_json::Map::new();
        config.insert("tag".into(), serde_json::json!("x"));
        config.insert("cors_origins".into(), serde_json::Value::Null);
        let patch = PluginPatch {
            enabled: Some(false),
            config: Some(config),
            ..Default::default()
        };
        let b = c.patch_plugin("web hook", "m/1", &patch).await.unwrap();
        assert_eq!((b.config_version, b.sealed), (4, true));
        let req = srv.await.unwrap();
        assert_eq!(req.method, "PATCH");
        assert_eq!(req.path, "/v2/admin/plugins/web%20hook/m%2F1");
        assert!(req.headers.contains("authorization: bearer admintok"));
        assert!(req.headers.contains("relay-access: acc-password"));
        let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"enabled": false, "config": {"tag": "x", "cors_origins": null}})
        );
        assert!(body.get("if_version").is_none() && body.get("space_id").is_none());

        let (base, srv) = one_shot("200 OK", BINDING_JSON).await;
        let c = V2Client::new(base, "", "t", true).unwrap();
        let patch = PluginPatch {
            box_name: Some("q".into()),
            if_version: 4,
            ..Default::default()
        };
        c.patch_plugin("drop", "m", &patch).await.unwrap();
        let req = srv.await.unwrap();
        assert!(!req.headers.contains("relay-access"));
        let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(body, serde_json::json!({"box_name": "q", "if_version": 4}));
    }

    #[tokio::test]
    async fn get_catalog_account_and_unsupported() {
        let (base, srv) = one_shot("200 OK", BINDING_JSON).await;
        let c = V2Client::new(base, "", "t", true).unwrap();
        assert_eq!(c.get_plugin("drop", "m").await.unwrap().id, "b1");
        let req = srv.await.unwrap();
        assert_eq!(
            (req.method.as_str(), req.path.as_str()),
            ("GET", "/v2/admin/plugins/drop/m")
        );

        let (base, srv) = one_shot(
            "200 OK",
            r#"{"ok":true,"registered":["drop"],"plugins":[{"id":"drop","required_trust":"bridge_allowed","schema":[{"key":"token","type":"string","secret":true}]}],"bindings":[]}"#,
        )
        .await;
        let c = V2Client::new(base, "", "t", true).unwrap();
        let cat = c.plugin_catalog().await.unwrap();
        assert_eq!(cat[0].schema[0].kind, "string");
        assert!(cat[0].schema[0].secret);
        let req = srv.await.unwrap();
        assert_eq!(
            (req.method.as_str(), req.path.as_str()),
            ("GET", "/v2/admin/plugins")
        );

        let (base, srv) = one_shot(
            "200 OK",
            r#"{"ok":true,"account":{"binding_id":"b1","scope_key":"k","username":"u","mode":"rw","meta_json":"","updated_at":1}}"#,
        )
        .await;
        let c = V2Client::new(base, "", "t", true).unwrap();
        let acct = c
            .upsert_plugin_account_password("webdav", "m", "k", "u", "pw", "rw")
            .await
            .unwrap();
        assert_eq!(acct.username, "u");
        let req = srv.await.unwrap();
        assert_eq!(
            (req.method.as_str(), req.path.as_str()),
            ("PUT", "/v2/admin/plugins/webdav/m/accounts")
        );
        let body: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"scope_key": "k", "username": "u", "password": "pw", "mode": "rw"})
        );
        assert!(body.get("secret_sha256").is_none());

        let (base, srv) = one_shot("404 Not Found", "404 page not found").await;
        let c = V2Client::new(base, "", "t", true).unwrap();
        let err = c
            .patch_plugin("drop", "m", &PluginPatch::default())
            .await
            .unwrap_err();
        assert!(err.is_unsupported(), "{err:?}");
        srv.await.unwrap();

        let (base, srv) = one_shot("404 Not Found", r#"{"ok":false,"error":"not found"}"#).await;
        let c = V2Client::new(base, "", "t", true).unwrap();
        let err = c.get_plugin("drop", "missing").await.unwrap_err();
        assert!(!err.is_unsupported());
        assert!(matches!(err, V2Error::Api { status: 404, .. }));
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn me_device_root_admin_and_unsupported() {
        let (base, srv) = one_shot(
            "200 OK",
            r#"{"ok":true,"device":{"id":"d1","name":"phone","public_key":"pk","is_admin":true,"revoked":false,"created_at":5}}"#,
        )
        .await;
        let c = V2Client::new(base, "acc-password", "tok", true).unwrap();
        let me = c.me().await.unwrap();
        assert!(!me.root_admin);
        assert_eq!(
            me.device,
            Some(Device {
                id: "d1".into(),
                name: "phone".into(),
                public_key: "pk".into(),
                is_admin: true,
                revoked: false,
                created_at: 5,
            })
        );
        let req = srv.await.unwrap();
        assert_eq!((req.method.as_str(), req.path.as_str()), ("GET", "/v2/me"));
        assert!(req.headers.contains("authorization: bearer tok"));
        assert!(req.headers.contains("relay-access: acc-password"));

        let (base, srv) = one_shot("200 OK", r#"{"ok":true,"root_admin":true}"#).await;
        let c = V2Client::new(base, "", "root", true).unwrap();
        let me = c.me().await.unwrap();
        assert!(me.root_admin && me.device.is_none());
        srv.await.unwrap();

        let (base, srv) = one_shot("404 Not Found", "404 page not found").await;
        let c = V2Client::new(base, "", "t", true).unwrap();
        let err = c.me().await.unwrap_err();
        assert!(err.is_unsupported(), "{err:?}");
        srv.await.unwrap();
    }
}
