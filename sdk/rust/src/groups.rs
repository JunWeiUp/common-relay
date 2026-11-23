//! Authenticated device groups: the signed membership chain and the durable group state
//! machine every client uses (create, invite, join, approve, rename, remove, exit).
//!
//! Every retryable step is saved through `save` before its HTTP mutation, so a lost reply or
//! a restart resumes the same signed entry instead of signing a new one. Transport is
//! injected via [`GroupApi`]; [`GroupHttp`] is the blocking HTTPS implementation. Domain
//! failures are [`Error::Relay`] codes (`ManagerRequired`, `ApprovalPending`,
//! `ApprovalConflict`, `AnotherJoinPending`, `VerificationCodeMismatch`, `LastManager`);
//! relay HTTP statuses are [`Error::Http`]; malformed data is [`Error::Invalid`].
use crate::access::{
    checked_access_password, valid_access_password, validate_endpoint, ACCESS_HEADER,
};
use crate::{invitation_links, validate_payload, Error, Options, PayloadKind, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn bad() -> Error {
    Error::Invalid("invalid group data")
}
fn code(name: &str) -> Error {
    Error::Relay(name.to_owned())
}
fn relay_code(name: &str) -> Error {
    code(name)
}
fn invalid<T>() -> Result<T> {
    Err(bad())
}
fn hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
fn unhex(s: &str) -> Result<Vec<u8>> {
    hex::decode(s).map_err(|_| bad())
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k).and_then(Value::as_str).ok_or_else(bad)
}
fn key32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| bad())
}
/// Raw signed payload bytes of an entry.
fn payload(entry: &Value) -> Result<Vec<u8>> {
    STANDARD.decode(text(entry, "payload")?).map_err(|_| bad())
}
/// Decode a signed payload only after strict byte-level validation.
pub fn unpack_group_entry(entry: &Value) -> Result<Value> {
    let bytes = payload(entry)?;
    if ![PayloadKind::State, PayloadKind::Request, PayloadKind::Grant]
        .into_iter()
        .any(|k| validate_payload(&bytes, k))
    {
        return invalid();
    }
    serde_json::from_slice(&bytes).map_err(|_| bad())
}
fn unpack(entry: &Value) -> Result<Value> {
    unpack_group_entry(entry)
}
/// Derive the Ed25519 signing key from a device's X25519 secret (hex).
pub fn group_signing_key(secret: &str) -> Result<SigningKey> {
    signing(&unhex(secret)?).map(|(_, key)| key)
}
/// `(public signing key bytes, signing key)` for a 32-byte device secret.
fn signing(secret: &[u8]) -> Result<([u8; 32], SigningKey)> {
    let secret = key32(secret)?;
    let mut h = Sha256::new();
    h.update(b"common-relay/group-signing/v1\0");
    h.update(secret);
    let key = SigningKey::from_bytes(&h.finalize().into());
    Ok((key.verifying_key().to_bytes(), key))
}
/// X25519 envelope public key (hex) of a 32-byte device secret.
fn envelope_key(secret: &[u8]) -> Result<String> {
    let secret = x25519_dalek::StaticSecret::from(key32(secret)?);
    Ok(hex(x25519_dalek::PublicKey::from(&secret).as_bytes()))
}
fn access_password(p: &str) -> Result<&str> {
    if valid_access_password(p) {
        Ok(p)
    } else {
        Err(Error::Invalid(
            "access password must be 8-128 printable ASCII characters without spaces",
        ))
    }
}
/// The server access password stored in a group config, if any.
fn configured_password(c: &Value) -> Result<Option<&str>> {
    match c.get("password") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(p)) if p.is_empty() => Ok(None),
        Some(Value::String(p)) => checked_access_password(Some(p)),
        Some(_) => invalid(),
    }
}
fn endpoint(raw: &str, local: bool) -> Result<url::Url> {
    validate_endpoint(
        raw,
        &Options {
            allow_local_test: local,
            password: None,
        },
    )
    .ok_or_else(bad)
}
fn key32_24(bytes: &[u8]) -> Result<[u8; 24]> {
    bytes.try_into().map_err(|_| bad())
}
fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; n];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| Error::Storage("system randomness unavailable"))?;
    Ok(bytes)
}
fn random() -> Result<String> {
    Ok(hex(&random_bytes(32)?))
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn name(s: &str) -> Result<&str> {
    let s = s.trim();
    if s.is_empty() || s.len() > 128 {
        return invalid();
    }
    Ok(s)
}
/// Unix seconds from an integer or fractional JSON number (older clients sent floats).
fn seconds(v: &Value) -> u64 {
    v.as_u64()
        .or_else(|| v.as_f64().filter(|f| *f >= 0.0).map(|f| f as u64))
        .unwrap_or(0)
}
fn erase(v: &mut Value, key: &str) {
    if let Some(o) = v.as_object_mut() {
        o.remove(key);
    }
}

pub(crate) fn canonical(v: &Value) -> Vec<u8> {
    fn write(v: &Value, out: &mut String) {
        match v {
            Value::Object(m) => {
                out.push('{');
                let sorted: BTreeMap<_, _> = m.iter().collect();
                for (i, (k, v)) in sorted.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&Value::String((*k).clone()).to_string());
                    out.push(':');
                    write(v, out);
                }
                out.push('}');
            }
            Value::Array(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(v, out);
                }
                out.push(']');
            }
            _ => out.push_str(&v.to_string()),
        }
    }
    let mut out = String::new();
    write(v, &mut out);
    out.into_bytes()
}
fn verify(entry: &Value, key: &str) -> Result<()> {
    let key: [u8; 32] = unhex(key)?.try_into().map_err(|_| bad())?;
    let pk = VerifyingKey::from_bytes(&key).map_err(|_| bad())?;
    let sig: [u8; 64] = unhex(text(entry, "signature")?)?
        .try_into()
        .map_err(|_| bad())?;
    pk.verify_strict(
        &payload(entry)?,
        &ed25519_dalek::Signature::from_bytes(&sig),
    )
    .map_err(|_| bad())
}
fn sign_value(value: &Value, secret: &[u8], device: &str) -> Result<Value> {
    let (_, key) = signing(secret)?;
    let bytes = canonical(value);
    Ok(
        json!({"payload":STANDARD.encode(&bytes),"signature":hex(&key.sign(&bytes).to_bytes()),"signer":device}),
    )
}
fn members(v: &Value) -> Result<&Vec<Value>> {
    v["members"].as_array().ok_or_else(bad)
}
fn valid_state(v: &Value) -> Result<()> {
    let ms = members(v)?;
    let closed = v["closed"] == true;
    let ids: BTreeSet<_> = ms.iter().map(|m| m["device"].as_str()).collect();
    if v["version"] != 1
        || ms.len() > 32
        || ids.len() != ms.len()
        || (closed && !ms.is_empty())
        || (!closed && !ms.iter().any(|m| m["manager"] == true))
    {
        return invalid();
    }
    Ok(())
}
fn advance(old_entry: &Value, entry: &Value) -> Result<Value> {
    let old = unpack(old_entry)?;
    let next = unpack(entry)?;
    valid_state(&next)?;
    let before = members(&old)?;
    let after = members(&next)?;
    let actor = before
        .iter()
        .find(|m| m["device"] == entry["signer"])
        .ok_or_else(bad)?;
    if old["closed"] == true
        || old["app"] != next["app"]
        || old["group"] != next["group"]
        || old["name"].as_str().unwrap_or("") != next["name"].as_str().unwrap_or("")
        || next["revision"].as_u64() != old["revision"].as_u64().and_then(|n| n.checked_add(1))
        || next["previous"] != digest(&payload(old_entry)?)
    {
        return invalid();
    }
    let added: Vec<_> = after
        .iter()
        .filter(|m| !before.iter().any(|b| b["device"] == m["device"]))
        .collect();
    let removed: Vec<_> = before
        .iter()
        .filter(|m| !after.iter().any(|b| b["device"] == m["device"]))
        .collect();
    if let Some(auth) = entry.get("authorization") {
        let grant = unpack(auth)?;
        if auth.get("authorization").is_some()
            || actor["manager"] != true
            || auth["signer"] != actor["device"]
        {
            return invalid();
        }
        verify(auth, text(actor, "signing_key")?)?;
        if grant["version"] != 1
            || grant["purpose"] != "common-relay/admission/v1"
            || grant["mode"] != "auto"
            || grant["app"] != old["app"]
            || grant["group"] != old["group"]
            || grant["anchor_revision"].as_u64().unwrap_or(0) < 1
            || grant["anchor_revision"].as_u64() > old["revision"].as_u64()
            || grant["expires"].as_u64().unwrap_or(0) == 0
        {
            return invalid();
        }
        for (k, n) in [
            ("invitation", 16),
            ("secret_hash", 32),
            ("delegate_key", 32),
            ("anchor_hash", 32),
        ] {
            if unhex(text(&grant, k)?)?.len() != n {
                return invalid();
            }
        }
        verify(entry, text(&grant, "delegate_key")?)?;
        if next["closed"] == true
            || next["invitation"] != grant["invitation"]
            || unhex(text(&next, "request_hash")?)?.len() != 32
            || after.len() != before.len() + 1
            || added.len() != 1
            || added[0]["manager"] != false
            || !before.iter().all(|m| after.contains(m))
        {
            return invalid();
        }
        if old["revision"] == grant["anchor_revision"]
            && grant["anchor_hash"] != digest(&payload(old_entry)?)
        {
            return invalid();
        }
    } else {
        verify(entry, text(actor, "signing_key")?)?;
        let changed: Vec<_> = after
            .iter()
            .filter(|m| before.iter().any(|b| b["device"] == m["device"] && b != *m))
            .collect();
        if !changed.is_empty() {
            if changed.len() != 1 || !added.is_empty() || !removed.is_empty() {
                return invalid();
            }
            let m = changed[0];
            let mut prior = before
                .iter()
                .find(|b| b["device"] == m["device"])
                .ok_or_else(bad)?
                .clone();
            // Only the display name may change in place; keys (including a missing
            // signing_key) can never be filled in or rotated without re-admission.
            prior["name"] = m["name"].clone();
            if prior != *m
                || !(actor["manager"] == true || m["device"] == actor["device"])
                || next["invitation"] != ""
                || next["request_hash"] != ""
            {
                return invalid();
            }
        } else {
            let empty = next["invitation"] == "" && next["request_hash"] == "";
            let add = actor["manager"] == true
                && added.len() == 1
                && removed.is_empty()
                && next["invitation"] != ""
                && next["request_hash"] != "";
            let remove = removed.len() == 1
                && added.is_empty()
                && empty
                && (actor["manager"] == true || removed[0]["device"] == actor["device"]);
            let close =
                next["closed"] == true && actor["manager"] == true && after.is_empty() && empty;
            if !(add || remove || close) {
                return invalid();
            }
        }
    }
    Ok(entry.clone())
}

/// Verify a signed transition against the previous authenticated entry.
pub fn advance_group(current: &Value, entry: &Value) -> Result<()> {
    advance(current, entry).map(|_| ())
}

pub trait GroupApi {
    fn call(
        &self,
        c: &Value,
        method: &str,
        path: &str,
        body: Option<Value>,
        auth: Option<String>,
    ) -> Result<Value>;
}
pub struct Groups<'a, A: GroupApi> {
    pub config: Value,
    pub api: A,
    pub save: &'a mut dyn FnMut(&Value) -> Result<()>,
    pub local: bool,
}
impl<A: GroupApi> Groups<'_, A> {
    fn persist(&mut self) -> Result<()> {
        (self.save)(&self.config)
    }
    fn call(&self, m: &str, p: &str, b: Option<Value>, a: Option<String>) -> Result<Value> {
        self.api.call(&self.config, m, p, b, a)
    }
    fn sign(&self, v: &Value) -> Result<Value> {
        sign_value(
            v,
            &unhex(text(&self.config, "secret_key")?)?,
            text(&self.config, "device")?,
        )
    }
    pub fn member(&self, n: &str) -> Result<Value> {
        let raw = unhex(text(&self.config, "secret_key")?)?;
        let (pk, _) = signing(&raw)?;
        Ok(
            json!({"device":self.config["device"],"name":n,"public_key":envelope_key(&raw)?,"signing_key":hex(&pk),"manager":false}),
        )
    }
    fn state(&self) -> Result<Value> {
        unpack(&self.config["group_entry"])
    }
    fn accept(&mut self, e: Value) -> Result<()> {
        let state = unpack(&e)?;
        valid_state(&state)?;
        if state["app"] != self.config["app"] || state["group"] != self.config["group"] {
            return invalid();
        }
        let mut peers = serde_json::Map::new();
        for m in state["members"].as_array().ok_or_else(bad)? {
            if m["device"] != self.config["device"] {
                peers.insert(text(m, "device")?.into(), m["public_key"].clone());
            }
        }
        self.config["group_entry"] = e;
        self.config["trusted_peers"] = Value::Object(peers);
        self.config["public_key"] = self.member("")?["public_key"].clone();
        Ok(())
    }
    pub fn refresh(&mut self) -> Result<Value> {
        let mut current = self.config["group_entry"].clone();
        for _ in 0..4096 {
            let old = unpack(&current)?;
            let reply = self.call(
                "GET",
                &format!("/group?after={}", old["revision"]),
                None,
                None,
            )?;
            let entries = reply["entries"].as_array().ok_or_else(bad)?;
            let online = reply["online"].clone();
            for e in entries {
                current = advance(&current, e)?;
                // Record the exact signed approval observed on the verified chain,
                // even when later changes are returned in the same history page.
                if self.config["pending_approval"]["entry"] == *e {
                    self.config["pending_approval"]["committed"] = json!(true);
                }
                // Local only: the relay keeps a spent invitation until it expires so the
                // joiner can replay its commit after a lost reply; it cannot be reused.
                self.retire_used_invitation(&unpack(e)?);
            }
            let revision = unpack(&current)?["revision"].as_u64().ok_or_else(bad)?;
            if entries.is_empty() || revision >= reply["revision"].as_u64().ok_or_else(bad)? {
                self.accept(current)?;
                self.persist()?;
                return Ok(json!({"state":self.state()?,"online":online}));
            }
            if revision <= old["revision"].as_u64().unwrap_or(0) {
                return invalid();
            }
        }
        invalid()
    }
    /// A device has joined with our issued invitation (its id is on a verified committed
    /// entry): the invitation is spent, so return to the normal state without the user
    /// cancelling it. An approval in progress finishes via `approve`.
    fn retire_used_invitation(&mut self, state: &Value) {
        let Some(issued) = self.config["issued_invitation"]["id"].as_str() else {
            return;
        };
        if issued.is_empty()
            || state["invitation"] != issued
            || self.config["pending_approval"].is_object()
        {
            return;
        }
        for key in ["issued_invitation", "pending_link", "join_request"] {
            erase(&mut self.config, key);
        }
    }
    pub fn create(&mut self, title: &str, device_name: &str) -> Result<()> {
        if self.config.get("group_entry").is_some() || self.config.get("pending_join").is_some() {
            return invalid();
        }
        if self.config.get("pending_create").is_none() {
            if self.config.get("group").is_some() {
                return invalid();
            }
            let title = name(title)?;
            let device_name = name(device_name)?;
            self.config["group"] = json!(format!("g-{}", &random()?[..32]));
            self.config["token"] = json!(random()?);
            let mut own = self.member(device_name)?;
            own["manager"] = json!(true);
            self.config["pending_create"]=self.sign(&json!({"version":1,"app":self.config["app"],"group":self.config["group"],"name":title,"revision":1,"previous":"","members":[own],"invitation":"","request_hash":""}))?;
            self.persist()?;
        }
        let e = self.config["pending_create"].clone();
        self.call(
            "POST",
            "/group/create",
            Some(json!({"entry":e,"token_hash":digest(text(&self.config,"token")?.as_bytes())})),
            None,
        )?;
        self.accept(e)?;
        erase(&mut self.config, "pending_create");
        self.persist()
    }
    /// Creates the group from an admin-issued bootstrap code (`common-relay group-bootstrap`)
    /// instead of self-service; members pinned in `trusted_peers` join without signing keys.
    pub fn bootstrap(&mut self, code: &Value, device_name: &str) -> Result<()> {
        if self.config.get("group_entry").is_some()
            || code["app"] != self.config["app"]
            || code["group"] != self.config["group"]
        {
            return invalid();
        }
        if self.config.get("pending_bootstrap").is_none() {
            if self
                .config
                .get("token")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                self.config["token"] = json!(random()?);
            }
            let mut own = self.member(name(device_name)?)?;
            own["manager"] = json!(true);
            let device = self.config["device"].clone();
            let mut members = vec![own];
            for (k, v) in self.config["trusted_peers"]
                .as_object()
                .into_iter()
                .flatten()
            {
                if *k != device {
                    members.push(json!({"device":k,"name":k,"public_key":v,"signing_key":"","manager":false}));
                }
            }
            self.config["pending_bootstrap"] = self.sign(&json!({"version":1,"app":code["app"],"group":code["group"],"revision":1,"previous":"","members":members,"invitation":"","request_hash":""}))?;
            self.persist()?;
        }
        let e = self.config["pending_bootstrap"].clone();
        self.call(
            "POST",
            "/group/bootstrap",
            Some(json!({"entry":e,"token_hash":digest(text(&self.config,"token")?.as_bytes())})),
            Some(format!("Bootstrap {}", text(code, "bootstrap")?)),
        )?;
        self.accept(e)?;
        erase(&mut self.config, "pending_bootstrap");
        self.persist()
    }
    fn manager(&self) -> Result<Value> {
        let state = self.state()?;
        let own = state["members"]
            .as_array()
            .ok_or_else(bad)?
            .iter()
            .find(|m| m["device"] == self.config["device"])
            .ok_or_else(bad)?;
        if own["manager"] != true {
            return Err(code("ManagerRequired"));
        }
        Ok(own.clone())
    }
    pub fn invite(&mut self, mode: &str) -> Result<String> {
        if self.config["pending_approval"].is_object() {
            return Err(code("ApprovalPending"));
        }
        if mode != "auto" && mode != "manual" {
            return invalid();
        }
        self.refresh()?;
        let own = self.manager()?;
        if self.config["issued_invitation"]["expires"]
            .as_u64()
            .unwrap_or(0)
            > now()
        {
            return self.publish();
        }
        let secret = random()?;
        let mut body = json!({"secret_hash":digest(secret.as_bytes())});
        let mut inv = json!({});
        if mode == "auto" {
            let delegate = random()?;
            let (key, _) = signing(&unhex(&delegate)?)?;
            let grant=self.sign(&json!({"version":1,"purpose":"common-relay/admission/v1","mode":"auto","app":self.config["app"],"group":self.config["group"],"invitation":&random()?[..32],"expires":now()+600,"secret_hash":body["secret_hash"],"delegate_key":hex(&key),"anchor_revision":self.state()?["revision"],"anchor_hash":digest(&payload(&self.config["group_entry"])?) }))?;
            body["mode"] = json!(mode);
            body["grant"] = grant.clone();
            inv["grant"] = grant;
            inv["delegate_secret"] = json!(delegate);
        }
        let result = self.call("POST", "/group/invitations", Some(body), None)?;
        if mode == "auto" {
            let grant = unpack(&inv["grant"])?;
            if result["mode"] != mode
                || result["id"] != grant["invitation"]
                || result["expires"] != grant["expires"]
            {
                return invalid();
            }
        }
        if unhex(text(&result, "id")?)?.len() != 16
            || result["expires"].as_u64().unwrap_or(0) <= now()
        {
            return invalid();
        }
        for (k,v) in json!({"version":1,"mode":mode,"url":self.config["url"],"app":self.config["app"],"group":self.config["group"],"id":result["id"],"expires":result["expires"],"secret":secret,"manager":own}).as_object().unwrap(){inv[k]=v.clone();}
        self.config["issued_invitation"] = inv;
        erase(&mut self.config, "join_request");
        self.persist()?;
        self.publish()
    }
    /// Publishes (or returns) the short link for the issued invitation; idempotent.
    pub fn publish(&mut self) -> Result<String> {
        let inv = &self.config["issued_invitation"];
        if let Some(link) = inv["short_link"].as_str() {
            return Ok(link.into());
        }
        // Keep packet/key stable across response loss and retries.
        if self.config.get("pending_link").is_none() {
            let key = random_bytes(32)?;
            let nonce = random_bytes(24)?;
            self.config["pending_link"] = json!({"key":STANDARD.encode(&key),"packet":invitation_links::seal(inv,&key32(&key)?,&key32_24(&nonce)?)?});
            self.persist()?;
        }
        let key = STANDARD
            .decode(text(&self.config["pending_link"], "key")?)
            .map_err(|_| bad())?;
        let id = text(&self.config["issued_invitation"], "id")?;
        self.call("POST",&format!("/group/invitations/{id}/link"),Some(json!({"read_hash":digest(invitation_links::read_token(&key32(&key)?).as_bytes()),"packet":self.config["pending_link"]["packet"]})),None)?;
        let mut inv = self.config["issued_invitation"].clone();
        if self.local {
            let original = text(&inv, "url")?.to_owned();
            inv["url"] = json!(original.replacen("ws:", "wss:", 1));
        }
        let link =
            invitation_links::make_link(&inv, &key32(&key)?, configured_password(&self.config)?)?;
        self.config["issued_invitation"]["short_link"] = json!(link);
        erase(&mut self.config, "pending_link");
        self.persist()?;
        Ok(link)
    }
    /// Resolves a short link. The access password comes from the link, else the user's typed
    /// password, else our own password only for our own relay; an explicit one is returned
    /// in the invitation so `join` can keep it.
    pub fn resolve(&self, link: &str, typed: Option<&str>) -> Result<Value> {
        self.resolve_with(link, typed, None)
    }
    /// Like [`Self::resolve`]; an explicit `override_password` (the user corrected it) wins
    /// over the link's password, and an empty override is rejected before any request.
    pub fn resolve_with(
        &self,
        link: &str,
        typed: Option<&str>,
        override_password: Option<&str>,
    ) -> Result<Value> {
        let (mut url, id, key, mut link_password) =
            invitation_links::parse_link(link.trim(), false)?;
        if let Some(p) = override_password {
            link_password = Some(access_password(p)?.to_owned());
        }
        if self.local && url::Url::parse(&url).map_err(|_| bad())?.host_str() == Some("127.0.0.1") {
            url = url.replacen("wss:", "ws:", 1);
        }
        let explicit = match (link_password, typed) {
            (Some(p), _) => Some(p),
            (None, Some(p)) => Some(access_password(p)?.to_owned()),
            (None, None) => None,
        };
        let password = match &explicit {
            Some(p) => Some(p.clone()),
            None if self.config["url"] == url => {
                configured_password(&self.config)?.map(str::to_owned)
            }
            None => None,
        };
        let result = self.api.call(
            &json!({"url":url,"password":password}),
            "GET",
            &format!("/enroll/{id}/link"),
            None,
            Some(format!(
                "InvitationLink {}",
                invitation_links::read_token(&key32(&key)?)
            )),
        )?;
        if result["version"] != 1 {
            return invalid();
        }
        let mut inv = invitation_links::open_packet(text(&result, "packet")?, &key32(&key)?)?;
        if inv["version"] != 1
            || inv["url"] != url
            || inv["id"] != id
            || inv["app"] != self.config["app"]
            || seconds(&inv["expires"]) <= now()
        {
            return invalid();
        }
        if let Some(p) = explicit {
            inv["password"] = json!(p);
        }
        Ok(inv)
    }
    fn grant(&self, inv: &Value) -> Result<Value> {
        let e = &inv["grant"];
        let m = &inv["manager"];
        let g = unpack(e)?;
        verify(e, text(m, "signing_key")?)?;
        if e.get("authorization").is_some()
            || m["manager"] != true
            || e["signer"] != m["device"]
            || g["version"] != 1
            || g["purpose"] != "common-relay/admission/v1"
            || g["mode"] != "auto"
            || g["app"] != inv["app"]
            || g["group"] != inv["group"]
            || g["invitation"] != inv["id"]
            || g["expires"] != inv["expires"]
            || g["secret_hash"] != digest(text(inv, "secret")?.as_bytes())
            || g["anchor_revision"].as_u64().unwrap_or(0) < 1
            || unhex(text(&g, "anchor_hash")?)?.len() != 32
        {
            return invalid();
        }
        let (key, _) = signing(&unhex(text(inv, "delegate_secret")?)?)?;
        if g["delegate_key"] != hex(&key) {
            return invalid();
        }
        Ok(g)
    }
    pub fn join(&mut self, inv: Value, n: &str) -> Result<bool> {
        if self.config.get("group_entry").is_some() || self.config.get("pending_create").is_some() {
            return invalid();
        }
        if inv["version"] != 1
            || inv["app"] != self.config["app"]
            || seconds(&inv["expires"]) <= now()
        {
            return invalid();
        }
        endpoint(text(&inv, "url")?, self.local)?;
        if inv["mode"] == "auto" {
            self.grant(&inv)?;
        } else if inv["mode"] != "manual" && !inv["mode"].is_null() {
            return invalid();
        }
        if self.config.get("pending_join").is_some() {
            if self.config["pending_join"]["invitation"] != inv {
                return Err(code("AnotherJoinPending"));
            }
        } else {
            self.config["url"] = inv["url"].clone();
            self.config["group"] = inv["group"].clone();
            if let Some(p) = inv.get("password").and_then(Value::as_str) {
                self.config["password"] = json!(access_password(p)?);
            }
            self.config["token"] = json!(random()?);
            let req=self.sign(&json!({"version":1,"app":self.config["app"],"group":self.config["group"],"invitation":inv["id"],"member":self.member(name(n)?)?,"token_hash":digest(text(&self.config,"token")?.as_bytes())}))?;
            self.config["pending_join"] = json!({"invitation":inv,"request":req});
            self.persist()?;
        }
        self.call(
            "POST",
            &format!("/enroll/{}", text(&inv, "id")?),
            Some(self.config["pending_join"]["request"].clone()),
            Some(format!("Invitation {}", text(&inv, "secret")?)),
        )?;
        self.finish_join()
    }
    /// Completes a pending join; `true` once this device is a member. Idempotent: an
    /// already completed join (e.g. automatic admission inside `join`) returns `true`.
    pub fn finish_join(&mut self) -> Result<bool> {
        if self.config.get("pending_join").is_none() && self.config.get("group_entry").is_some() {
            return Ok(true);
        }
        let pending = self.config["pending_join"].clone();
        let inv = &pending["invitation"];
        let request = &pending["request"];
        let req = unpack(request)?;
        let id = text(inv, "id")?;
        let auth = Some(format!("Claim {}", text(&self.config, "token")?));
        let e = if inv["mode"] == "auto" {
            let grant = self.grant(inv)?;
            let anchor = grant["anchor_revision"].as_u64().ok_or_else(bad)?;
            let mut after = anchor - 1;
            let mut current: Option<Value> = None;
            let mut result = json!({});
            for _ in 0..4096 {
                result = self.call(
                    "GET",
                    &format!("/enroll/{id}/auto?after={after}"),
                    None,
                    auth.clone(),
                )?;
                let entries = result["entries"].as_array().ok_or_else(bad)?;
                let latest = result["revision"].as_u64().ok_or_else(bad)?;
                if entries.is_empty() || latest < anchor || latest > 4096 {
                    return invalid();
                }
                for e in entries {
                    current = Some(if let Some(old) = current {
                        advance(&old, e)?
                    } else {
                        let state = unpack(e)?;
                        if state["app"] != inv["app"]
                            || state["group"] != inv["group"]
                            || digest(&payload(e)?) != grant["anchor_hash"]
                            || state["revision"] != anchor
                        {
                            return invalid();
                        }
                        e.clone()
                    });
                }
                let revision = unpack(current.as_ref().ok_or_else(bad)?)?["revision"]
                    .as_u64()
                    .ok_or_else(bad)?;
                if revision <= after || revision > latest {
                    return invalid();
                }
                after = revision;
                if after == latest {
                    break;
                }
            }
            let current = current.ok_or_else(bad)?;
            if result["entry"].is_object() {
                if result["entry"] != current {
                    return invalid();
                }
                current
            } else {
                let mut state = unpack(&current)?;
                state["members"]
                    .as_array_mut()
                    .ok_or_else(bad)?
                    .push(req["member"].clone());
                state["revision"] = json!(after + 1);
                state["previous"] = json!(digest(&payload(&current)?));
                state["invitation"] = inv["id"].clone();
                state["request_hash"] = json!(digest(&payload(request)?));
                let mut e = sign_value(
                    &state,
                    &unhex(text(inv, "delegate_secret")?)?,
                    text(&inv["manager"], "device")?,
                )?;
                e["authorization"] = inv["grant"].clone();
                advance(&current, &e)?;
                self.config["pending_join"]["auto_entry"] = e.clone();
                self.persist()?;
                let reply =
                    self.call("POST", &format!("/enroll/{id}/auto"), Some(e.clone()), auth)?;
                if reply != e {
                    return invalid();
                }
                e
            }
        } else {
            let result = self.call("GET", &format!("/enroll/{id}"), None, auth)?;
            if result["entry"].is_null() {
                return Ok(false);
            }
            let e = result["entry"].clone();
            if e.get("authorization").is_some() {
                return invalid();
            }
            verify(&e, text(&inv["manager"], "signing_key")?)?;
            e
        };
        let state = unpack(&e)?;
        let own = state["members"]
            .as_array()
            .ok_or_else(bad)?
            .iter()
            .find(|m| m["device"] == self.config["device"])
            .ok_or_else(bad)?;
        let mut expected = req["member"].clone();
        if inv["mode"] != "auto" {
            expected["manager"] = own["manager"].clone();
        }
        if state["app"] != self.config["app"]
            || state["group"] != self.config["group"]
            || state["closed"] == true
            || e["signer"] != inv["manager"]["device"]
            || state["invitation"] != inv["id"]
            || state["request_hash"] != digest(&payload(request)?)
            || *own != expected
            || (inv["mode"] == "auto" && e["authorization"] != inv["grant"])
        {
            return invalid();
        }
        self.accept(e)?;
        erase(&mut self.config, "pending_join");
        self.persist()?;
        Ok(true)
    }
    pub fn pending(&mut self) -> Result<()> {
        if self.config["pending_approval"].is_object() {
            return Ok(());
        }
        let inv = &self.config["issued_invitation"];
        if inv["mode"] == "auto" {
            return invalid();
        }
        let result = self.call(
            "GET",
            &format!("/group/invitations/{}", text(inv, "id")?),
            None,
            None,
        )?;
        if result["request"].is_null() {
            erase(&mut self.config, "join_request");
        } else {
            let e = &result["request"];
            let req = unpack(e)?;
            if req["app"] != self.config["app"]
                || req["group"] != self.config["group"]
                || req["invitation"] != inv["id"]
                || e["signer"] != req["member"]["device"]
            {
                return invalid();
            }
            verify(e, text(&req["member"], "signing_key")?)?;
            self.config["join_request"] = e.clone();
        }
        self.persist()
    }
    pub fn code(&self) -> Result<String> {
        let req = if self.config["pending_join"].is_object() {
            &self.config["pending_join"]["request"]
        } else {
            &self.config["join_request"]
        };
        let h = digest(&payload(req)?)[..12].to_uppercase();
        Ok(format!("{}-{}-{}", &h[..4], &h[4..8], &h[8..12]))
    }
    fn change(&mut self, mut state: Value) -> Result<()> {
        let old = &self.config["group_entry"];
        state["revision"] = json!(state["revision"].as_u64().ok_or_else(bad)? + 1);
        state["previous"] = json!(digest(&payload(old)?));
        let e = self.sign(&state)?;
        advance(old, &e)?;
        self.call("PUT", "/group", Some(e.clone()), None)?;
        self.accept(e)?;
        self.persist()
    }
    pub fn approve(&mut self, code: &str, manager: bool) -> Result<()> {
        if code != self.code()? {
            return Err(relay_code("VerificationCodeMismatch"));
        }
        if self.config["pending_approval"].is_object() {
            if self.config["pending_approval"]["manager"] != manager {
                return invalid();
            }
            return self.finish_approval();
        }
        self.refresh()?;
        self.manager()?;
        let req = unpack(&self.config["join_request"])?;
        let inv = &self.config["issued_invitation"];
        if seconds(&inv["expires"]) <= now() || req["invitation"] != inv["id"] {
            return invalid();
        }
        verify(
            &self.config["join_request"],
            text(&req["member"], "signing_key")?,
        )?;
        let mut m = req["member"].clone();
        m["manager"] = json!(manager);
        let mut state = self.state()?;
        let members = state["members"].as_array_mut().ok_or_else(bad)?;
        members.retain(|v| v["device"] != m["device"]);
        members.push(m);
        state["invitation"] = inv["id"].clone();
        state["request_hash"] = json!(digest(&payload(&self.config["join_request"])?));
        state["revision"] = json!(state["revision"].as_u64().ok_or_else(bad)? + 1);
        state["previous"] = json!(digest(&payload(&self.config["group_entry"])?));
        let entry = self.sign(&state)?;
        advance(&self.config["group_entry"], &entry)?;
        self.config["pending_approval"] =
            json!({"entry":entry,"manager":manager,"committed":false});
        self.persist()?; // Persist the exact user-confirmed request before PUT.
        self.finish_approval()
    }
    fn finish_approval(&mut self) -> Result<()> {
        let entry = self.config["pending_approval"]["entry"].clone();
        self.refresh()?;
        if self.config["pending_approval"]["committed"] != true {
            let candidate = unpack(&entry)?;
            let current = self.state()?;
            if current["revision"].as_u64().ok_or_else(bad)?
                >= candidate["revision"].as_u64().ok_or_else(bad)?
            {
                // A different signed entry occupies this revision. Never rebase
                // an old confirmation onto another request or changed identity.
                return Err(code("ApprovalConflict"));
            }
            advance(&self.config["group_entry"], &entry)?;
            self.call("PUT", "/group", Some(entry.clone()), None)?;
            self.accept(entry.clone())?;
            self.config["pending_approval"]["committed"] = json!(true);
            self.persist()?;
        }
        // A separate access transaction may resume after this membership commit.
        self.config["approval_receipt"] = entry;
        erase(&mut self.config, "pending_approval");
        erase(&mut self.config, "issued_invitation");
        erase(&mut self.config, "join_request");
        self.persist()
    }
    pub fn cancel(&mut self) -> Result<()> {
        if self.config["pending_approval"].is_object() {
            self.refresh()?;
            if self.config["pending_approval"]["committed"] == true {
                // Membership is already committed. Complete its local receipt;
                // the access intent has been cancelled separately by the caller.
                self.finish_approval()?;
            } else {
                let candidate = unpack(&self.config["pending_approval"]["entry"])?;
                if self.state()?["revision"].as_u64().ok_or_else(bad)?
                    < candidate["revision"].as_u64().ok_or_else(bad)?
                {
                    return Err(code("ApprovalPending"));
                }
                // A verified different entry has occupied the candidate's slot.
                erase(&mut self.config, "pending_approval");
                self.persist()?;
            }
        }
        if self.config["issued_invitation"].is_null() {
            return Ok(());
        }
        self.call(
            "DELETE",
            &format!(
                "/group/invitations/{}",
                text(&self.config["issued_invitation"], "id")?
            ),
            None,
            None,
        )?;
        for k in ["issued_invitation", "pending_link", "join_request"] {
            erase(&mut self.config, k);
        }
        self.persist()
    }
    pub fn rename(&mut self, device: &str, n: &str) -> Result<()> {
        let n = name(n)?;
        self.refresh()?;
        let mut state = self.state()?;
        let m = state["members"]
            .as_array_mut()
            .ok_or_else(bad)?
            .iter_mut()
            .find(|m| m["device"] == device)
            .ok_or_else(bad)?;
        if m["name"] == n {
            return Ok(());
        }
        m["name"] = json!(n);
        state["invitation"] = json!("");
        state["request_hash"] = json!("");
        self.change(state)
    }
    pub fn remove(&mut self, device: &str) -> Result<()> {
        if self.config["device"] == device {
            return invalid();
        }
        self.refresh()?;
        self.manager()?;
        let mut state = self.state()?;
        state["members"]
            .as_array_mut()
            .ok_or_else(bad)?
            .retain(|m| m["device"] != device);
        state["invitation"] = json!("");
        state["request_hash"] = json!("");
        self.change(state)
    }
    /// The signed exit (or disband) entry for the current verified state, checked against
    /// the chain rules. Fails when the exit is not allowed (e.g. the last manager leaving
    /// other members behind, or a non-manager disbanding).
    fn exit_entry(&self, disband: bool) -> Result<Value> {
        let mut state = self.state()?;
        if disband {
            self.manager()?;
        }
        let own = self.config["device"].clone();
        let members = state["members"].as_array_mut().ok_or_else(bad)?;
        members.retain(|m| !disband && m["device"] != own);
        if members.is_empty() {
            state["closed"] = json!(true);
        } else if !members.iter().any(|m| m["manager"] == true) {
            return Err(code("LastManager"));
        }
        state["invitation"] = json!("");
        state["request_hash"] = json!("");
        state["revision"] = json!(state["revision"].as_u64().ok_or_else(bad)? + 1);
        state["previous"] = json!(digest(&payload(&self.config["group_entry"])?));
        let e = self.sign(&state)?;
        advance(&self.config["group_entry"], &e)?;
        Ok(e)
    }
    /// Offline pre-check so a client can clear local state first (owner policy) only when the
    /// signed exit it will send afterwards is valid. Uses the locally verified state.
    pub fn check_exit(&self, disband: bool) -> Result<()> {
        if self.config["exit_completed"] == true || self.config.get("group_entry").is_none() {
            return Ok(());
        }
        self.exit_entry(disband).map(|_| ())
    }
    pub fn exit(&mut self, disband: bool) -> Result<()> {
        if self.config["exit_completed"] == true {
            return Ok(());
        }
        if self.config.get("pending_exit").is_some() {
            if self.config["exit_disband"] != disband {
                return invalid();
            }
        } else {
            self.refresh()?;
            let e = self.exit_entry(disband)?;
            self.config["pending_exit"] = e;
            self.config["exit_disband"] = json!(disband);
            self.persist()?;
        }
        let e = self.config["pending_exit"].clone();
        match self.call("POST", "/group/exit", Some(e.clone()), None) {
            Ok(_) => {}
            Err(e) => {
                if matches!(e, Error::Http(409)) {
                    erase(&mut self.config, "pending_exit");
                    self.persist()?;
                }
                return Err(e);
            }
        }
        self.accept(e)?;
        erase(&mut self.config, "pending_exit");
        self.config["exit_completed"] = json!(true);
        self.persist()
    }
}

const LIMIT: usize = 3 * 1024 * 1024;

pub struct GroupHttp {
    /// Allow `ws://127.0.0.1` relays (tests only).
    pub local: bool,
}

pub(crate) fn client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| Error::Connection("relay request failed"))
}

/// `https://host/relay/v1` (or `/v2`) for a relay WebSocket endpoint.
pub(crate) fn base(url: &str, local: bool) -> Result<String> {
    let mut url = endpoint(url, local)?;
    url.set_scheme(if url.scheme() == "wss" {
        "https"
    } else {
        "http"
    })
    .map_err(|_| bad())?;
    let prefix = if url.path() == "/v2/ws" {
        "/v2"
    } else {
        "/relay/v1"
    };
    Ok(format!(
        "{}://{}{}",
        url.scheme(),
        &url[url::Position::BeforeHost..url::Position::AfterPort],
        prefix
    ))
}

pub(crate) fn read_limited(
    response: reqwest::blocking::Response,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    response
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Connection("relay request failed"))?;
    if bytes.len() > LIMIT {
        return invalid();
    }
    Ok(bytes)
}

impl GroupHttp {
    /// Checks a group config's endpoint and access password without any request.
    pub fn check(&self, c: &Value) -> Result<()> {
        base(text(c, "url")?, self.local)?;
        configured_password(c)?;
        Ok(())
    }
}

impl GroupApi for GroupHttp {
    fn call(
        &self,
        c: &Value,
        method: &str,
        path: &str,
        body: Option<Value>,
        auth: Option<String>,
    ) -> Result<Value> {
        let base = base(text(c, "url")?, self.local)?;
        if !path.starts_with('/') || path.contains('#') || path.contains("..") {
            return invalid();
        }
        let mut request = client()?
            .request(method.parse().map_err(|_| bad())?, format!("{base}{path}"))
            .header(
                "Authorization",
                auth.unwrap_or_else(|| format!("Bearer {}", c["token"].as_str().unwrap_or(""))),
            );
        if let Some(password) = configured_password(c)? {
            request = request.header(ACCESS_HEADER, password);
        }
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(canonical(&body));
        }
        let response = request
            .send()
            .map_err(|_| Error::Connection("relay request failed"))?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(Error::Http(status));
        }
        let value: Value = serde_json::from_slice(&read_limited(response)?).map_err(|_| bad())?;
        if !value.is_object() {
            return invalid();
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
        text(v, k)
    }
    #[test]
    fn group_vectors() {
        let v: Value =
            serde_json::from_str(include_str!("../../../protocol/v2/group-vectors.json")).unwrap();
        verify(&v["initial"], field(&v["manager"], "signing_key").unwrap()).unwrap();
        verify(
            &v["request"],
            field(&v["new_member"], "signing_key").unwrap(),
        )
        .unwrap();
        assert_eq!(
            json!(hex(&signing(
                &unhex(field(&v["config"], "secret_key").unwrap()).unwrap()
            )
            .unwrap()
            .0)),
            v["manager"]["signing_key"]
        );
        for (a, b) in [
            ("initial", "approved"),
            ("approved", "removed"),
            ("approved", "left"),
            ("approved", "disbanded"),
            ("approved", "renamed"),
        ] {
            advance_group(&v[a], &v[b]).unwrap_or_else(|e| panic!("{a} -> {b}: {e}"));
        }
        for b in ["unauthorized_disband", "unauthorized_rename"] {
            assert!(advance_group(&v["approved"], &v[b]).is_err(), "{b}");
        }
        assert!(advance_group(&v["initial"], &v["removed"]).is_err());
        verify(
            &v["self_service"],
            field(&v["manager"], "signing_key").unwrap(),
        )
        .unwrap();
        advance_group(&v["initial"], &v["auto_admission"]["approved"]).unwrap();
        for case in v["auto_admission"]["invalid"].as_array().unwrap() {
            assert!(
                advance_group(&v["initial"], &case["entry"]).is_err(),
                "{}",
                case["case"]
            );
        }
        for (k, base, ok) in [
            ("valid", "approved", true),
            ("invalid", "approved", false),
            ("invalid_auto", "initial", false),
        ] {
            for case in v["strict_payload"][k].as_array().unwrap() {
                assert_eq!(
                    advance_group(&v[base], &case["entry"]).is_ok(),
                    ok,
                    "{}",
                    case["case"]
                );
            }
        }
    }
    #[test]
    fn group_entry_hash_vectors() {
        let v: Value =
            serde_json::from_str(include_str!("../../../protocol/v2/group-vectors.json")).unwrap();
        let entry =
            |path: &str| -> Value { path.split('.').fold(v.clone(), |acc, k| acc[k].clone()) };
        let digest = |e: &Value| {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(field(e, "payload").unwrap())
                .unwrap();
            hex::encode(Sha256::digest(raw))
        };
        let cases = v["entry_hashes"]["cases"].as_array().unwrap();
        assert!(!cases.is_empty());
        for c in cases {
            let name = c["entry"].as_str().unwrap();
            let e = entry(name);
            assert_eq!(digest(&e), c["payload_sha256"].as_str().unwrap(), "{name}");
            assert_eq!(
                verify(&e, c["verify_key"].as_str().unwrap()).is_ok(),
                c["signature_valid"].as_bool().unwrap(),
                "{name}"
            );
        }
        let links = v["entry_hashes"]["links"].as_array().unwrap();
        assert!(!links.is_empty());
        for l in links {
            let (base, next) = (l["base"].as_str().unwrap(), l["next"].as_str().unwrap());
            let payload = super::payload(&entry(next)).unwrap();
            let payload: Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(
                payload["previous"].as_str().unwrap(),
                digest(&entry(base)),
                "{base} -> {next}"
            );
        }
    }
    /// In-memory relay: accepts writes and serves the verified chain back.
    #[derive(Default)]
    struct MemoryRelay {
        entries: std::cell::RefCell<Vec<Value>>,
        calls: std::cell::RefCell<Vec<String>>,
    }
    impl GroupApi for &MemoryRelay {
        fn call(
            &self,
            _c: &Value,
            method: &str,
            path: &str,
            body: Option<Value>,
            _a: Option<String>,
        ) -> Result<Value> {
            self.calls.borrow_mut().push(format!("{method} {path}"));
            let mut entries = self.entries.borrow_mut();
            match (method, path.split('?').next().unwrap_or("")) {
                ("POST", "/group/create") => entries.push(body.unwrap()["entry"].clone()),
                ("PUT", "/group") | ("POST", "/group/exit") => entries.push(body.unwrap()),
                ("GET", "/group") => {
                    let after: usize = path.rsplit('=').next().unwrap().parse().unwrap();
                    let newer: Vec<Value> = entries.iter().skip(after).cloned().collect();
                    return Ok(json!({"entries": newer, "revision": entries.len(), "online": []}));
                }
                _ => return Err(Error::Http(404)),
            }
            Ok(json!({}))
        }
    }

    #[test]
    fn drafts_are_saved_before_the_request_that_commits_them() {
        let relay = MemoryRelay::default();
        let mut saved = Vec::new();
        let mut save = |c: &Value| {
            saved.push(c.clone());
            Ok(())
        };
        let mut groups = Groups {
            config: json!({"app":"example","url":"wss://relay.example/v2/ws","device":"mac","secret_key":random().unwrap()}),
            api: &relay,
            save: &mut save,
            local: false,
        };
        groups.create("Home", "Mac").unwrap();
        assert!(groups.config["pending_create"].is_null());
        groups.rename("mac", "MacBook").unwrap();
        assert_eq!(
            unpack(&groups.config["group_entry"]).unwrap()["members"][0]["name"],
            "MacBook"
        );
        assert!(groups.create("Again", "Mac").is_err(), "already enrolled");
        assert!(
            groups.finish_join().unwrap(),
            "a member's finish_join is a no-op"
        );
        groups.exit(true).unwrap();
        assert_eq!(groups.config["exit_completed"], true);
        let closed = unpack(&groups.config["group_entry"]).unwrap();
        assert_eq!(closed["closed"], true);
        assert_eq!(closed["revision"], 3);
        assert_eq!(relay.calls.borrow()[0], "POST /group/create");
        drop(groups);
        assert!(saved[0]["pending_create"].is_object());
    }

    fn keep(_: &Value) -> Result<()> {
        Ok(())
    }
    #[test]
    fn https_uses_bundled_tls_provider_and_never_follows_redirects() {
        use std::io::{Read, Write};
        let tls = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let tls_addr = tls.local_addr().unwrap();
        std::thread::spawn(move || while tls.accept().is_ok() {});
        let c = json!({"url":format!("wss://{tls_addr}/v2/ws"),"token":"test-only"});
        assert!(GroupHttp { local: false }
            .call(&c, "GET", "/group", None, None)
            .is_err());

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut buf = [0; 4096];
            let _ = socket.read(&mut buf).unwrap();
            socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/stolen\r\nContent-Length: 0\r\n\r\n").unwrap();
        });
        let c = json!({"url":format!("ws://{addr}/v2/ws"),"token":"test-only"});
        assert!(matches!(
            GroupHttp { local: true }.call(&c, "GET", "/group", None, None),
            Err(Error::Http(302))
        ));
        server.join().unwrap();
    }
    #[test]
    fn local_server_group_lifecycle() {
        struct Server(std::process::Child, std::path::PathBuf);
        impl Drop for Server {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
                let _ = std::fs::remove_dir_all(&self.1);
            }
        }
        let binary =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../build/common-relay");
        if !binary.exists() {
            eprintln!("skipped: prebuilt relay unavailable");
            return;
        }
        let data = std::env::temp_dir().join(format!("relay-rust-group-{}", random().unwrap()));
        std::fs::create_dir(&data).unwrap();
        let credential = data.join("bootstrap.json");
        let password = "{{SECRET_ovfdztxk}}";
        let access = data.join("access.sha256");
        std::fs::write(&access, hex::encode(Sha256::digest(password.as_bytes()))).unwrap();
        let admin = data.join("admin.sha256");
        std::fs::write(&admin, hex::encode(Sha256::digest(b"test-v2-admin-secret"))).unwrap();
        assert!(std::process::Command::new(&binary)
            .args([
                "group-bootstrap",
                "--data",
                data.to_str().unwrap(),
                "--app",
                "example",
                "--group",
                "bootstrap-test",
                "--credential-out",
                credential.to_str().unwrap()
            ])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap()
            .success());
        let code: Value = serde_json::from_slice(&std::fs::read(&credential).unwrap()).unwrap();
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);
        let proc = std::process::Command::new(binary)
            .args([
                "serve",
                "--data",
                data.to_str().unwrap(),
                "--listen",
                &addr.to_string(),
                "--disk-reserve",
                "0",
                "--self-service-apps",
                "example",
                "--access-password-file",
                access.to_str().unwrap(),
                "--v2-admin-hash-file",
                admin.to_str().unwrap(),
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let _server = Server(proc, data);
        let mut ready = false;
        for _ in 0..100 {
            if std::net::TcpStream::connect(addr).is_ok() {
                ready = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(30));
        }
        assert!(ready);
        let url = format!("ws://{addr}/v2/ws");
        let config = |device: &str| json!({"url":url,"password":password,"app":"example","device":device,"secret_key":random().unwrap()});
        let groups = |config: Value| Groups {
            config,
            api: GroupHttp { local: true },
            save: Box::leak(Box::new(keep)),
            local: true,
        };
        let mut initial = config("bootstrap-manager");
        initial["group"] = json!("bootstrap-test");
        let mut boot = groups(initial);
        boot.bootstrap(&code, "Bootstrap").unwrap();
        boot.refresh().unwrap();
        let mut a = groups(config("creator"));
        a.create("Devices", "Creator").unwrap();
        let link = a.invite("auto").unwrap();
        assert!(link.contains('.'), "the link carries the access password");
        // A fresh device without a configured password learns it from the scanned link.
        let mut c = config("phone");
        c.as_object_mut().unwrap().remove("password");
        let mut b = groups(c);
        let resolved = b.resolve(&link, None).unwrap();
        assert_eq!(resolved["password"], password);
        assert!(b.join(resolved, "Phone").unwrap());
        assert_eq!(b.config["password"], password);
        a.refresh().unwrap();
        assert!(
            a.config.get("issued_invitation").is_none(),
            "a spent invitation retires"
        );
        // Manual admission: both sides compare the code, then the manager approves.
        let manual = a.invite("manual").unwrap();
        let mut t = groups(config("tablet"));
        let resolved = t.resolve(&manual, None).unwrap();
        assert!(!t.join(resolved, "Tablet").unwrap());
        a.pending().unwrap();
        assert_eq!(a.code().unwrap(), t.code().unwrap());
        let code = a.code().unwrap();
        a.approve(&code, false).unwrap();
        assert!(t.finish_join().unwrap());
        // Group members exchange an end-to-end encrypted file over /v2/files.
        let options = crate::Options {
            allow_local_test: true,
            password: Some(password.into()),
        };
        let identity = |g: &Groups<GroupHttp>| {
            crate::Identity::new(
                "example",
                g.config["group"].as_str().unwrap(),
                g.config["device"].as_str().unwrap(),
                g.config["secret_key"].as_str().unwrap(),
                serde_json::from_value::<HashMap<String, String>>(
                    g.config["trusted_peers"].clone(),
                )
                .unwrap(),
            )
            .unwrap()
        };
        a.refresh().unwrap();
        let (ia, it) = (identity(&a), identity(&t));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let files_a = crate::RelayFiles::for_relay_endpoint(
            &url,
            a.config["token"].as_str().unwrap(),
            options.clone(),
        )
        .unwrap();
        let files_t = crate::RelayFiles::for_relay_endpoint(
            &url,
            t.config["token"].as_str().unwrap(),
            options,
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!("relay-rust-files-{}", random().unwrap()));
        std::fs::create_dir(&dir).unwrap();
        let source = dir.join("source.bin");
        std::fs::write(&source, b"v2 file payload ".repeat(4096)).unwrap();
        let staged = dir.join("staged.enc");
        let descriptor = crate::prepare_file(
            &ia,
            "tablet",
            &source,
            &staged,
            json!({"name":"source.bin"}),
        )
        .unwrap();
        runtime
            .block_on(files_a.upload(&descriptor, &staged))
            .unwrap();
        let inbox = runtime.block_on(files_t.inbox()).unwrap();
        assert_eq!(inbox.len(), 1);
        let downloaded = dir.join("download.enc");
        runtime
            .block_on(files_t.download(&inbox[0], &downloaded))
            .unwrap();
        let output = dir.join("out.bin");
        let meta = crate::decrypt_file(&it, "creator", &inbox[0], &downloaded, &output).unwrap();
        assert_eq!(meta["name"], "source.bin");
        assert_eq!(
            std::fs::read(&output).unwrap(),
            std::fs::read(&source).unwrap()
        );
        runtime.block_on(files_t.delete(&inbox[0].id)).unwrap();
        assert!(runtime.block_on(files_t.inbox()).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
        t.exit(false).unwrap();
        a.refresh().unwrap();
        b.rename("phone", "Renamed").unwrap();
        a.refresh().unwrap();
        // The last manager cannot leave members behind; it can disband.
        assert!(matches!(a.check_exit(false), Err(Error::Relay(c)) if c == "LastManager"));
        b.exit(false).unwrap();
        a.refresh().unwrap();
        a.exit(true).unwrap();
        assert_eq!(a.config["exit_completed"], true);
    }
}
