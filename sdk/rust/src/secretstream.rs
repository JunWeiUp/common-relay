//! libsodium `crypto_secretstream_xchacha20poly1305` over RustCrypto primitives.
//! Byte-compatible with libsodium; checked against the shared vectors and Python interop.

use chacha20::cipher::consts::U10;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::{hchacha, ChaCha20};
use poly1305::universal_hash::KeyInit;
use poly1305::Poly1305;
use serde_json::{json, Value};
use zeroize::Zeroize;

use crate::crypto::random;
use crate::{Error, Result};

pub(crate) const TAG_MESSAGE: u8 = 0;
pub(crate) const TAG_FINAL: u8 = 3;
const TAG_REKEY: u8 = 2;
/// Tag byte plus Poly1305 MAC.
pub(crate) const ABYTES: usize = 17;
/// Largest plaintext per record, so a record never exceeds 65536 bytes.
pub(crate) const MAX_RECORD_PLAIN: usize = 65536 - ABYTES;
const MAX_RECORD: usize = 65536;

/// Subkey plus `counter[4, little-endian] | inonce[8]`, as in libsodium.
struct State {
    key: [u8; 32],
    nonce: [u8; 12],
}

impl Drop for State {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
    }
}

impl State {
    fn new(key: &[u8; 32], header: &[u8; 24]) -> Self {
        let mut subkey: [u8; 32] = hchacha::<U10>(key.into(), header[..16].into()).into();
        let mut nonce = [0u8; 12];
        nonce[0] = 1;
        nonce[4..].copy_from_slice(&header[16..]);
        let state = Self { key: subkey, nonce };
        subkey.zeroize();
        state
    }

    fn cipher(&self, block: u64) -> ChaCha20 {
        let mut c = ChaCha20::new(&self.key.into(), &self.nonce.into());
        c.seek(block * 64);
        c
    }

    fn mac(&self, ad: &[u8], block: &[u8; 64], ciphertext: &[u8]) -> [u8; 16] {
        let mut poly_key = [0u8; 64];
        self.cipher(0).apply_keystream(&mut poly_key);
        let poly = Poly1305::new(poly_key[..32].into());
        poly_key.zeroize();
        // libsodium pads the ciphertext with `(0x10 - 64 + mlen) & 0xf` zero bytes, which is
        // `mlen % 16`, not the usual AEAD padding; the whole message is therefore hashed unpadded.
        let ad_pad = (16 - ad.len() % 16) % 16;
        let c_pad = ciphertext.len() % 16;
        let mut message =
            Vec::with_capacity(ad.len() + ad_pad + 64 + ciphertext.len() + c_pad + 16);
        message.extend_from_slice(ad);
        message.resize(ad.len() + ad_pad, 0);
        message.extend_from_slice(block);
        message.extend_from_slice(ciphertext);
        message.resize(message.len() + c_pad, 0);
        message.extend_from_slice(&(ad.len() as u64).to_le_bytes());
        message.extend_from_slice(&(64 + ciphertext.len() as u64).to_le_bytes());
        let tag = poly.compute_unpadded(&message).into();
        message.zeroize();
        tag
    }

    fn advance(&mut self, mac: &[u8; 16], tag: u8) {
        for (n, m) in self.nonce[4..].iter_mut().zip(mac) {
            *n ^= m;
        }
        let counter =
            u32::from_le_bytes(self.nonce[..4].try_into().expect("counter")).wrapping_add(1);
        self.nonce[..4].copy_from_slice(&counter.to_le_bytes());
        if tag & TAG_REKEY != 0 || counter == 0 {
            self.rekey();
        }
    }

    fn rekey(&mut self) {
        let mut next = [0u8; 40];
        next[..32].copy_from_slice(&self.key);
        next[32..].copy_from_slice(&self.nonce[4..]);
        self.cipher(0).apply_keystream(&mut next);
        self.key.copy_from_slice(&next[..32]);
        self.nonce[4..].copy_from_slice(&next[32..]);
        self.nonce[..4].copy_from_slice(&1u32.to_le_bytes());
        next.zeroize();
    }
}

fn decode_descriptor(descriptor: &Value) -> Result<([u8; 32], [u8; 24])> {
    let field = |name: &str| descriptor.get(name).and_then(Value::as_str);
    let (Some(key), Some(header)) = (field("key"), field("header")) else {
        return Err(Error::Crypto("invalid stream descriptor"));
    };
    let mut k = [0u8; 32];
    let mut h = [0u8; 24];
    let lower = |s: &str| {
        s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if !lower(key)
        || !lower(header)
        || hex::decode_to_slice(key, &mut k).is_err()
        || hex::decode_to_slice(header, &mut h).is_err()
    {
        k.zeroize();
        return Err(Error::Crypto("invalid stream descriptor"));
    }
    Ok((k, h))
}

/// Sending half: a fresh random key and header per direction.
pub(crate) struct EncryptStream {
    state: State,
    key: [u8; 32],
    header: [u8; 24],
    pub(crate) finished: bool,
}

impl Drop for EncryptStream {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl EncryptStream {
    pub(crate) fn new() -> Result<Self> {
        let key = random::<32>()?;
        let header = random::<24>()?;
        Ok(Self::with_key(key, header))
    }

    pub(crate) fn with_key(key: [u8; 32], header: [u8; 24]) -> Self {
        Self {
            state: State::new(&key, &header),
            key,
            header,
            finished: false,
        }
    }

    /// The `{key, header}` value carried inside the authenticated envelope.
    pub(crate) fn descriptor(&self) -> Value {
        json!({"key": hex::encode(self.key), "header": hex::encode(self.header)})
    }

    #[cfg(test)]
    pub(crate) fn rekey_for_test(&mut self) {
        self.state.rekey();
    }

    pub(crate) fn push(&mut self, plain: &[u8], ad: &[u8], final_record: bool) -> Result<Vec<u8>> {
        if self.finished {
            return Err(Error::Invalid("stream already finished"));
        }
        if plain.len() > MAX_RECORD_PLAIN {
            return Err(Error::Invalid("stream record too large"));
        }
        let tag = if final_record { TAG_FINAL } else { TAG_MESSAGE };
        let mut block = [0u8; 64];
        block[0] = tag;
        self.state.cipher(1).apply_keystream(&mut block);
        let mut out = Vec::with_capacity(plain.len() + ABYTES);
        out.push(block[0]);
        out.extend_from_slice(plain);
        self.state.cipher(2).apply_keystream(&mut out[1..]);
        let mac = self.state.mac(ad, &block, &out[1..]);
        out.extend_from_slice(&mac);
        self.state.advance(&mac, tag);
        self.finished = final_record;
        Ok(out)
    }
}

/// Receiving half. Any failure leaves the state unchanged; callers abort the stream.
pub(crate) struct DecryptStream {
    state: State,
    pub(crate) finished: bool,
}

impl DecryptStream {
    pub(crate) fn new(descriptor: &Value) -> Result<Self> {
        let (mut key, header) = decode_descriptor(descriptor)?;
        let state = State::new(&key, &header);
        key.zeroize();
        Ok(Self {
            state,
            finished: false,
        })
    }

    /// Returns the plaintext; only MESSAGE and FINAL tags are accepted, nothing after FINAL.
    pub(crate) fn pull(&mut self, record: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        if self.finished {
            return Err(Error::Crypto("stream record after final"));
        }
        if !(ABYTES..=MAX_RECORD).contains(&record.len()) {
            return Err(Error::Crypto("invalid stream record size"));
        }
        let body = &record[1..record.len() - 16];
        let mut block = [0u8; 64];
        block[0] = record[0];
        self.state.cipher(1).apply_keystream(&mut block);
        let tag = block[0];
        block[0] = record[0];
        let mac = self.state.mac(ad, &block, body);
        let expected = &record[record.len() - 16..];
        let diff = mac
            .iter()
            .zip(expected)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff != 0 {
            return Err(Error::Crypto("stream record authentication failed"));
        }
        if tag != TAG_MESSAGE && tag != TAG_FINAL {
            return Err(Error::Crypto("unsupported stream tag"));
        }
        let mut plain = body.to_vec();
        self.state.cipher(2).apply_keystream(&mut plain);
        self.state.advance(&mac, tag);
        self.finished = tag == TAG_FINAL;
        Ok(plain)
    }
}

/// `[1,app,group,sender,recipient,kind,id,sequence]` without whitespace.
pub(crate) fn aad(
    app: &str,
    group: &str,
    sender: &str,
    recipient: &str,
    kind: &str,
    id: &str,
    sequence: u64,
) -> Vec<u8> {
    serde_json::to_vec(&json!([
        1, app, group, sender, recipient, kind, id, sequence
    ]))
    .expect("JSON value")
}
