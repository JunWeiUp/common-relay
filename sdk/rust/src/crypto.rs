use std::collections::HashMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use crypto_box::aead::Aead;
use crypto_box::SalsaBox;
use serde_json::{json, Value};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{Error, Result};

pub(crate) const MAX_ENVELOPE: usize = 262144;
const MAX_MESSAGE: usize = 192000;

fn lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(crate) fn valid_id(value: &str) -> bool {
    lower_hex(value, 32)
}
pub(crate) fn valid_key(value: &str) -> bool {
    lower_hex(value, 64)
}
pub(crate) fn valid_name(value: &str) -> bool {
    (1..=80).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn decode_key(value: &str) -> Result<[u8; 32]> {
    if !valid_key(value) {
        return Err(Error::Invalid("expected a 32-byte lowercase hex key"));
    }
    let mut key = [0u8; 32];
    hex::decode_to_slice(value, &mut key)
        .map_err(|_| Error::Invalid("expected a 32-byte lowercase hex key"))?;
    Ok(key)
}

pub(crate) fn random<const N: usize>() -> Result<[u8; N]> {
    let mut data = [0u8; N];
    getrandom::getrandom(&mut data).map_err(|_| Error::Crypto("system randomness unavailable"))?;
    Ok(data)
}

/// Generates local Curve25519 keys as `(secret_key, public_key)`. Never send the secret to the relay.
pub fn generate_key_pair() -> Result<(String, String)> {
    let secret = StaticSecret::from(random::<32>()?);
    let public = PublicKey::from(&secret);
    Ok((
        hex::encode(secret.to_bytes()),
        hex::encode(public.as_bytes()),
    ))
}

/// A local key and a copy of the out-of-band pinned trust map.
pub struct Identity {
    pub(crate) app: String,
    pub(crate) group: String,
    pub(crate) device: String,
    public: String,
    trusted: HashMap<String, SalsaBox>,
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("app", &self.app)
            .field("group", &self.group)
            .field("device", &self.device)
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    if value.len() > MAX_ENVELOPE {
        return Err(Error::Crypto("envelope too large"));
    }
    match STANDARD.decode(value) {
        Ok(raw) if STANDARD.encode(&raw) == value => Ok(raw),
        _ => Err(Error::Crypto("invalid base64")),
    }
}

pub(crate) fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

impl Identity {
    pub fn new<I, K, V>(
        app: &str,
        group: &str,
        device: &str,
        secret_key: &str,
        trusted_peers: I,
    ) -> Result<Self>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: AsRef<str>,
    {
        if !valid_name(app) || !valid_name(group) || !valid_name(device) {
            return Err(Error::Invalid("invalid identity name"));
        }
        let secret = StaticSecret::from(decode_key(secret_key)?);
        let public = hex::encode(PublicKey::from(&secret).as_bytes());
        let box_secret = crypto_box::SecretKey::from(secret.to_bytes());
        let mut trusted = HashMap::new();
        for (name, raw) in trusted_peers {
            let peer = decode_key(raw.as_ref())?;
            if !secret
                .diffie_hellman(&PublicKey::from(peer))
                .was_contributory()
            {
                return Err(Error::Invalid("invalid peer key"));
            }
            trusted.insert(
                name.into(),
                SalsaBox::new(&crypto_box::PublicKey::from(peer), &box_secret),
            );
        }
        Ok(Self {
            app: app.into(),
            group: group.into(),
            device: device.into(),
            public,
            trusted,
        })
    }

    pub fn public_key(&self) -> &str {
        &self.public
    }

    fn context(&self, from: &str, to: &str, kind: &str, id: &str) -> [Value; 7] {
        [
            json!(1),
            json!(self.app),
            json!(self.group),
            json!(from),
            json!(to),
            json!(kind),
            json!(id),
        ]
    }

    /// Seals `{context, value}` for a trusted peer. `kind` is message, stream.open, stream.accept or file.
    pub(crate) fn seal_value(
        &self,
        to: &str,
        kind: &str,
        id: &str,
        value: Value,
    ) -> Result<String> {
        if !valid_id(id) {
            return Err(Error::Invalid("invalid object ID"));
        }
        let peer = self
            .trusted
            .get(to)
            .ok_or(Error::Invalid("untrusted peer"))?;
        let plain = json!({"context": self.context(&self.device, to, kind, id), "value": value});
        let nonce = random::<24>()?;
        let sealed = peer
            .encrypt(
                &nonce.into(),
                serde_json::to_vec(&plain).expect("JSON value").as_slice(),
            )
            .map_err(|_| Error::Crypto("encryption failed"))?;
        let body = STANDARD.encode([nonce.as_slice(), &sealed].concat());
        if body.len() > MAX_ENVELOPE {
            return Err(Error::Invalid("encrypted message exceeds 256 KiB"));
        }
        Ok(body)
    }

    pub fn seal_message(&self, to: &str, id: &str, data: &[u8]) -> Result<String> {
        if !valid_id(id) || data.len() > MAX_MESSAGE {
            return Err(Error::Invalid("invalid ID or message too large"));
        }
        self.seal_value(to, "message", id, json!({"data": STANDARD.encode(data)}))
    }

    /// Offline envelopes also authenticate the absolute expiry sent to the relay.
    pub(crate) fn seal_offline_message(
        &self,
        to: &str,
        id: &str,
        data: &[u8],
        expires: i64,
    ) -> Result<String> {
        if !valid_id(id) || data.len() > MAX_MESSAGE {
            return Err(Error::Invalid("invalid ID or message too large"));
        }
        self.seal_value(
            to,
            "message",
            id,
            json!({"data": STANDARD.encode(data), "expires": expires}),
        )
    }

    /// Opens and authenticates an envelope; the value is an object or null.
    pub(crate) fn open_value(&self, from: &str, kind: &str, id: &str, body: &str) -> Result<Value> {
        if !valid_id(id) {
            return Err(Error::Invalid("invalid object ID"));
        }
        let peer = self
            .trusted
            .get(from)
            .ok_or(Error::Crypto("untrusted peer"))?;
        let raw = decode_base64(body)?;
        if raw.len() < 40 {
            return Err(Error::Crypto("truncated envelope"));
        }
        let nonce: [u8; 24] = raw[..24].try_into().expect("nonce length");
        let plain = peer
            .decrypt(&nonce.into(), &raw[24..])
            .map_err(|_| Error::Crypto("envelope authentication failed"))?;
        let mut envelope: Value =
            serde_json::from_slice(&plain).map_err(|_| Error::Crypto("invalid envelope JSON"))?;
        let value = match &mut envelope {
            Value::Object(fields) => fields.remove("value").unwrap_or(Value::Null),
            Value::Null => Value::Null,
            _ => return Err(Error::Crypto("invalid envelope JSON")),
        };
        if !matches!(value, Value::Object(_) | Value::Null) {
            return Err(Error::Crypto("invalid envelope JSON"));
        }
        // Compare numbers by value so `1` and `1.0` are both the version, as in the other SDKs.
        let expected = self.context(from, &self.device, kind, id);
        let matches = match envelope.get("context") {
            Some(Value::Array(items)) => {
                items.len() == expected.len()
                    && items[0].as_f64() == Some(1.0)
                    && items[1..].iter().zip(&expected[1..]).all(|(a, b)| a == b)
            }
            _ => false,
        };
        if !matches {
            return Err(Error::Crypto("authenticated context mismatch"));
        }
        Ok(value)
    }

    /// Returns the data and authenticated expiry without comparing it to the clock.
    pub(crate) fn open_message_parts(
        &self,
        from: &str,
        id: &str,
        body: &str,
    ) -> Result<(Vec<u8>, Option<i64>)> {
        let value = self.open_value(from, "message", id, body)?;
        let expires = match value.get("expires") {
            None => None,
            Some(expires) => match expires.as_i64() {
                Some(expiry) if expiry <= 9007199254740991 => Some(expiry),
                _ => return Err(Error::Crypto("invalid or expired message")),
            },
        };
        let data = match value.get("data") {
            None | Some(Value::Null) => return Err(Error::Crypto("missing message data")),
            Some(Value::String(data)) => decode_base64(data)?,
            Some(_) => return Err(Error::Crypto("invalid envelope JSON")),
        };
        Ok((data, expires))
    }

    pub fn open_message(&self, from: &str, id: &str, body: &str) -> Result<Vec<u8>> {
        let (data, expires) = self.open_message_parts(from, id, body)?;
        if expires.is_some_and(|expiry| expiry <= now()) {
            return Err(Error::Crypto("invalid or expired message"));
        }
        Ok(data)
    }

    pub(crate) fn device(&self) -> &str {
        &self.device
    }
}

/// A random 16-byte lowercase hex object ID. Save it before an offline send so retries reuse it.
pub fn new_message_id() -> Result<String> {
    Ok(hex::encode(random::<16>()?))
}
