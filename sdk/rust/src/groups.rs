//! Authenticated device group management.
use crate::{validate_payload, Error, PayloadKind, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

fn invalid() -> Error {
    Error::Invalid("invalid group data")
}
fn field<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v.get(k).and_then(Value::as_str).ok_or_else(invalid)
}
fn number(v: &Value, k: &str) -> Result<u64> {
    v.get(k).and_then(Value::as_u64).ok_or_else(invalid)
}
fn boolean(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or(false)
}
fn bytes32(s: &str) -> Result<[u8; 32]> {
    hex::decode(s)
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())
}
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn random(n: usize) -> Result<String> {
    let mut b = vec![0; n];
    getrandom::getrandom(&mut b).map_err(|_| invalid())?;
    Ok(hex::encode(b))
}
/// Derive the Ed25519 signing key from a device's X25519 secret.
pub fn group_signing_key(secret: &str) -> Result<SigningKey> {
    let mut h = Sha256::new();
    h.update(b"common-relay/group-signing/v1\0");
    h.update(bytes32(secret)?);
    Ok(SigningKey::from_bytes(&h.finalize().into()))
}
fn raw(e: &Value) -> Result<Vec<u8>> {
    STANDARD.decode(field(e, "payload")?).map_err(|_| invalid())
}
/// Decode a signed payload only after strict byte-level validation.
pub fn unpack_group_entry(e: &Value) -> Result<Value> {
    let b = raw(e)?;
    if ![PayloadKind::State, PayloadKind::Request, PayloadKind::Grant]
        .into_iter()
        .any(|k| validate_payload(&b, k))
    {
        return Err(invalid());
    }
    serde_json::from_slice(&b).map_err(|_| invalid())
}
fn sign(v: &Value, secret: &str, device: &str) -> Result<Value> {
    let b = serde_json::to_vec(v).map_err(|_| invalid())?;
    Ok(
        json!({"payload":STANDARD.encode(&b),"signature":hex::encode(group_signing_key(secret)?.sign(&b).to_bytes()),"signer":device}),
    )
}
fn verify(e: &Value, key: &str) -> Result<()> {
    let key = VerifyingKey::from_bytes(&bytes32(key)?).map_err(|_| invalid())?;
    let sig = hex::decode(field(e, "signature")?).map_err(|_| invalid())?;
    let sig = Signature::from_slice(&sig).map_err(|_| invalid())?;
    key.verify(&raw(e)?, &sig).map_err(|_| invalid())
}
fn members(v: &Value) -> Result<&Vec<Value>> {
    v.get("members")
        .and_then(Value::as_array)
        .ok_or_else(invalid)
}
fn validate_state(v: &Value, app: &str, group: &str) -> Result<()> {
    let m = members(v)?;
    let closed = boolean(v, "closed");
    if number(v, "version")? != 1
        || field(v, "app")? != app
        || field(v, "group")? != group
        || m.len() > 32
        || (closed && !m.is_empty())
        || (!closed && m.is_empty())
    {
        return Err(invalid());
    }
    let mut ids = HashSet::new();
    for x in m {
        if !ids.insert(field(x, "device")?) {
            return Err(invalid());
        }
    }
    if !closed && !m.iter().any(|x| boolean(x, "manager")) {
        return Err(invalid());
    }
    Ok(())
}
fn hex_len(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn grant(e: &Value, owner: &Value, state: &Value) -> Result<Value> {
    if !e.get("authorization").is_none_or(Value::is_null)
        || !boolean(owner, "manager")
        || field(e, "signer")? != field(owner, "device")?
    {
        return Err(invalid());
    }
    verify(e, field(owner, "signing_key")?)?;
    let g = unpack_group_entry(e)?;
    if number(&g, "version")? != 1
        || field(&g, "purpose")? != "common-relay/admission/v1"
        || field(&g, "mode")? != "auto"
        || field(&g, "app")? != field(state, "app")?
        || field(&g, "group")? != field(state, "group")?
        || number(&g, "anchor_revision")? == 0
        || number(&g, "anchor_revision")? > number(state, "revision")?
        || number(&g, "expires")? == 0
    {
        return Err(invalid());
    }
    for (k, n) in [
        ("invitation", 32),
        ("secret_hash", 64),
        ("delegate_key", 64),
        ("anchor_hash", 64),
    ] {
        if !hex_len(field(&g, k)?, n) {
            return Err(invalid());
        }
    }
    Ok(g)
}
/// Verify a signed transition against the previous authenticated entry.
pub fn advance_group(current: &Value, entry: &Value) -> Result<()> {
    let old = unpack_group_entry(current)?;
    let new = unpack_group_entry(entry)?;
    validate_state(&new, field(&old, "app")?, field(&old, "group")?)?;
    let actor = members(&old)?
        .iter()
        .find(|m| m["device"] == entry["signer"])
        .ok_or_else(invalid)?;
    if boolean(&old, "closed")
        || old.get("name").and_then(Value::as_str).unwrap_or("")
            != new.get("name").and_then(Value::as_str).unwrap_or("")
        || number(&new, "revision")? != number(&old, "revision")? + 1
        || field(&new, "previous")? != hash(&raw(current)?)
    {
        return Err(invalid());
    }
    let before: HashMap<_, _> = members(&old)?
        .iter()
        .map(|m| (m["device"].as_str().unwrap_or(""), m))
        .collect();
    let after: HashMap<_, _> = members(&new)?
        .iter()
        .map(|m| (m["device"].as_str().unwrap_or(""), m))
        .collect();
    if let Some(auth) = entry.get("authorization").filter(|a| !a.is_null()) {
        let g = grant(auth, actor, &old)?;
        verify(entry, field(&g, "delegate_key")?)?;
        let added: Vec<_> = after
            .iter()
            .filter(|(k, _)| !before.contains_key(*k))
            .collect();
        if boolean(&new, "closed")
            || field(&new, "invitation")? != field(&g, "invitation")?
            || !hex_len(field(&new, "request_hash")?, 64)
            || added.len() != 1
            || boolean(added[0].1, "manager")
            || after.len() != before.len() + 1
            || before.iter().any(|(k, v)| after.get(k) != Some(v))
            || (number(&old, "revision")? == number(&g, "anchor_revision")?
                && hash(&raw(current)?) != field(&g, "anchor_hash")?)
        {
            return Err(invalid());
        }
        return Ok(());
    }
    verify(entry, field(actor, "signing_key")?)?;
    let mut upgrades = HashSet::new();
    let mut renamed = HashSet::new();
    for (k, a) in &before {
        if let Some(b) = after.get(k) {
            if a != b {
                let mut same = (*a).clone();
                same["name"] = b["name"].clone();
                if &same == *b {
                    renamed.insert(*k);
                } else if a["signing_key"] == ""
                    && b["signing_key"].as_str().is_some_and(|s| !s.is_empty())
                    && a["public_key"] == b["public_key"]
                {
                    upgrades.insert(*k);
                } else {
                    return Err(invalid());
                }
            }
        }
    }
    let added = after.keys().filter(|k| !before.contains_key(*k)).count() + upgrades.len();
    let removed: Vec<_> = before.keys().filter(|k| !after.contains_key(*k)).collect();
    let empty = field(&new, "invitation")?.is_empty() && field(&new, "request_hash")?.is_empty();
    if !renamed.is_empty() {
        if renamed.len() != 1
            || added != 0
            || !removed.is_empty()
            || !empty
            || !(boolean(actor, "manager") || renamed.contains(field(entry, "signer")?))
        {
            return Err(invalid());
        }
        return Ok(());
    }
    if (boolean(&new, "closed") && boolean(actor, "manager") && after.is_empty() && empty)
        || (boolean(actor, "manager")
            && added == 1
            && removed.is_empty()
            && !field(&new, "invitation")?.is_empty()
            && !field(&new, "request_hash")?.is_empty())
        || (removed.len() == 1
            && added == 0
            && empty
            && (boolean(actor, "manager") || *removed[0] == field(entry, "signer")?))
    {
        Ok(())
    } else {
        Err(invalid())
    }
}

fn member(c: &Value, name: &str) -> Result<Value> {
    let secret = bytes32(field(c, "secret_key")?)?;
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
    Ok(
        json!({"device":field(c,"device")?,"name":name,"public_key":hex::encode(public.as_bytes()),"signing_key":hex::encode(group_signing_key(field(c,"secret_key")?)?.verifying_key().as_bytes()),"manager":false}),
    )
}
fn now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| invalid())?
        .as_secs())
}
/// Group operations mutate `config`; persist it after every operation, including errors.
pub struct Groups {
    pub config: Value,
    base: String,
    local: bool,
    http: reqwest::Client,
}
impl Groups {
    pub fn new(config: Value, allow_local_test: bool) -> Result<Self> {
        let u = url::Url::parse(field(&config, "url")?).map_err(|_| invalid())?;
        if !u.username().is_empty()
            || u.password().is_some()
            || u.query().is_some()
            || u.fragment().is_some()
            || u.path() != "/relay/v1/ws"
            || !(u.scheme() == "wss"
                || (allow_local_test && u.scheme() == "ws" && u.host_str() == Some("127.0.0.1")))
        {
            return Err(invalid());
        }
        let mut base = u.clone();
        base.set_scheme(if u.scheme() == "wss" { "https" } else { "http" })
            .map_err(|_| invalid())?;
        base.set_path("/relay/v1");
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|_| invalid())?;
        Ok(Self {
            config,
            base: base.to_string().trim_end_matches('/').to_owned(),
            local: allow_local_test,
            http,
        })
    }
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        value: Option<&Value>,
        auth: Option<String>,
    ) -> Result<Value> {
        let token = self
            .config
            .get("token")
            .and_then(Value::as_str)
            .unwrap_or("");
        let mut req = self
            .http
            .request(method, format!("{}{path}", self.base))
            .header(
                "Authorization",
                auth.unwrap_or_else(|| format!("Bearer {token}")),
            );
        if let Some(v) = value {
            req = req.json(v);
        }
        let mut res = req.send().await.map_err(|e| Error::Relay(e.to_string()))?;
        if res.status() != reqwest::StatusCode::OK {
            return Err(Error::Relay(format!("http {}", res.status().as_u16())));
        }
        let mut data = Vec::new();
        while let Some(chunk) = res.chunk().await.map_err(|e| Error::Relay(e.to_string()))? {
            data.extend_from_slice(&chunk);
            if data.len() > 3 * 1024 * 1024 {
                return Err(invalid());
            }
        }
        serde_json::from_slice(&data).map_err(|_| invalid())
    }
    fn accept(&mut self, e: &Value) -> Result<()> {
        let s = unpack_group_entry(e)?;
        let device = field(&self.config, "device")?;
        let mut peers = serde_json::Map::new();
        for m in members(&s)? {
            if field(m, "device")? != device {
                peers.insert(field(m, "device")?.to_owned(), m["public_key"].clone());
            }
        }
        let public = member(&self.config, device)?["public_key"].clone();
        self.config["group_entry"] = e.clone();
        self.config["trusted_peers"] = Value::Object(peers);
        self.config["public_key"] = public;
        Ok(())
    }
    fn ensure_token(&mut self) -> Result<()> {
        if self.config.get("token").is_none() {
            self.config["token"] = json!(random(32)?);
        }
        Ok(())
    }
    fn remove_key(&mut self, k: &str) {
        if let Some(m) = self.config.as_object_mut() {
            m.remove(k);
        }
    }
    pub async fn refresh(&mut self) -> Result<Value> {
        let mut current = self
            .config
            .get("group_entry")
            .filter(|v| !v.is_null())
            .cloned()
            .ok_or_else(invalid)?;
        loop {
            let revision = number(&unpack_group_entry(&current)?, "revision")?;
            let r = self
                .call(
                    reqwest::Method::GET,
                    &format!("/group?after={revision}"),
                    None,
                    None,
                )
                .await?;
            let entries = r["entries"].as_array().ok_or_else(invalid)?;
            for e in entries {
                advance_group(&current, e)?;
                current = e.clone();
            }
            self.accept(&current)?;
            if entries.is_empty()
                || number(&unpack_group_entry(&current)?, "revision")? >= number(&r, "revision")?
            {
                return Ok(json!({"state":unpack_group_entry(&current)?,"online":r["online"]}));
            }
        }
    }
    pub fn prepare_create(&mut self, group_name: &str, device_name: &str) -> Result<()> {
        if self.config.get("group_entry").is_some_and(|v| !v.is_null())
            || self
                .config
                .get("pending_join")
                .is_some_and(|v| !v.is_null())
        {
            return Err(invalid());
        }
        if self
            .config
            .get("pending_create")
            .is_some_and(|v| !v.is_null())
        {
            return Ok(());
        }
        let g = group_name.trim();
        let d = device_name.trim();
        if g.is_empty()
            || g.len() > 128
            || d.is_empty()
            || d.len() > 128
            || self
                .config
                .get("group")
                .and_then(Value::as_str)
                .is_some_and(|x| !x.is_empty())
        {
            return Err(invalid());
        }
        self.config["group"] = json!(format!("g-{}", random(16)?));
        self.ensure_token()?;
        let mut own = member(&self.config, d)?;
        own["manager"] = json!(true);
        let state = json!({"version":1,"app":self.config["app"],"group":self.config["group"],"name":g,"revision":1,"previous":"","members":[own],"invitation":"","request_hash":""});
        self.config["pending_create"] = sign(
            &state,
            field(&self.config, "secret_key")?,
            field(&self.config, "device")?,
        )?;
        Ok(())
    }
    pub async fn create(&mut self) -> Result<()> {
        let e = self
            .config
            .get("pending_create")
            .cloned()
            .ok_or_else(invalid)?;
        self.call(
            reqwest::Method::POST,
            "/group/create",
            Some(&json!({"entry":e,"token_hash":hash(field(&self.config,"token")?.as_bytes())})),
            None,
        )
        .await?;
        self.accept(&e)?;
        self.remove_key("pending_create");
        Ok(())
    }
    pub async fn bootstrap(&mut self, code: &Value, name: &str) -> Result<()> {
        if code["app"] != self.config["app"] || code["group"] != self.config["group"] {
            return Err(invalid());
        }
        self.ensure_token()?;
        let mut own = member(&self.config, name)?;
        own["manager"] = json!(true);
        let mut ms = vec![own];
        if let Some(peers) = self.config.get("trusted_peers").and_then(Value::as_object) {
            for (k, v) in peers {
                if k != field(&self.config, "device")? {
                    ms.push(json!({"device":k,"name":k,"public_key":v,"signing_key":"","manager":false}));
                }
            }
        }
        let state = json!({"version":1,"app":code["app"],"group":code["group"],"revision":1,"previous":"","members":ms,"invitation":"","request_hash":""});
        let e = sign(
            &state,
            field(&self.config, "secret_key")?,
            field(&self.config, "device")?,
        )?;
        self.call(
            reqwest::Method::POST,
            "/group/bootstrap",
            Some(&json!({"entry":e,"token_hash":hash(field(&self.config,"token")?.as_bytes())})),
            Some(format!("Bootstrap {}", field(code, "bootstrap")?)),
        )
        .await?;
        self.accept(&e)
    }
    pub async fn invite(&mut self, mode: &str, compact: bool) -> Result<Value> {
        if mode != "manual" && mode != "auto" {
            return Err(invalid());
        }
        self.refresh().await?;
        let current = self.config["group_entry"].clone();
        let s = unpack_group_entry(&current)?;
        let own = members(&s)?
            .iter()
            .find(|m| m["device"] == self.config["device"])
            .ok_or_else(invalid)?
            .clone();
        if !boolean(&own, "manager") {
            return Err(invalid());
        }
        let secret = random(32)?;
        let mut data = json!({"secret_hash":hash(secret.as_bytes())});
        let mut extra = None;
        if mode == "auto" {
            let delegate = random(32)?;
            let g = json!({"version":1,"purpose":"common-relay/admission/v1","mode":"auto","app":s["app"],"group":s["group"],"invitation":random(16)?,"expires":now()?+600,"secret_hash":data["secret_hash"],"delegate_key":hex::encode(group_signing_key(&delegate)?.verifying_key().as_bytes()),"anchor_revision":s["revision"],"anchor_hash":hash(&raw(&current)?)});
            let e = sign(
                &g,
                field(&self.config, "secret_key")?,
                field(&self.config, "device")?,
            )?;
            data["mode"] = json!(mode);
            data["grant"] = e.clone();
            extra = Some((e, delegate));
        }
        let r = self
            .call(
                reqwest::Method::POST,
                "/group/invitations",
                Some(&data),
                None,
            )
            .await?;
        if let Some((e, _)) = &extra {
            let g = unpack_group_entry(e)?;
            if r["mode"] != "auto" || r["id"] != g["invitation"] || r["expires"] != g["expires"] {
                return Err(invalid());
            }
        }
        let mut inv = json!({"version":1,"mode":mode,"url":self.config["url"],"app":self.config["app"],"group":self.config["group"],"id":r["id"],"expires":r["expires"],"secret":secret,"manager":own});
        if let Some((e, d)) = extra {
            inv["grant"] = e;
            inv["delegate_secret"] = json!(d);
        }
        if compact {
            let mut key = [0u8; 32];
            let mut nonce = [0u8; 24];
            getrandom::getrandom(&mut key).map_err(|_| invalid())?;
            getrandom::getrandom(&mut nonce).map_err(|_| invalid())?;
            let packet = crate::invitation_links::seal(&inv, &key, &nonce)?;
            let token = crate::invitation_links::read_token(&key);
            self.call(
                reqwest::Method::POST,
                &format!("/group/invitations/{}/link", field(&inv, "id")?),
                Some(&json!({"read_hash":hash(token.as_bytes()),"packet":packet})),
                None,
            )
            .await?;
            inv["short_link"] = json!(crate::invitation_links::make_link(&inv, &key)?);
        }
        Ok(inv)
    }
    pub async fn resolve_invitation(&self, text: &str) -> Result<Value> {
        let (url, id, key) = crate::invitation_links::parse_link(text.trim(), self.local)?;
        let endpoint = Groups::new(json!({"url":url}), self.local)?;
        let r = endpoint
            .call(
                reqwest::Method::GET,
                &format!("/enroll/{id}/link"),
                None,
                Some(format!(
                    "InvitationLink {}",
                    crate::invitation_links::read_token(&key)
                )),
            )
            .await?;
        if number(&r, "version")? != 1 {
            return Err(invalid());
        }
        let inv = crate::invitation_links::open_packet(field(&r, "packet")?, &key)?;
        if number(&inv, "version")? != 1
            || field(&inv, "url")? != url
            || field(&inv, "id")? != id
            || inv["app"] != self.config["app"]
            || number(&inv, "expires")? <= now()?
        {
            return Err(invalid());
        }
        Ok(inv)
    }
    pub async fn pending(&self, inv: &Value) -> Result<Value> {
        let r = self
            .call(
                reqwest::Method::GET,
                &format!("/group/invitations/{}", field(inv, "id")?),
                None,
                None,
            )
            .await?;
        let e = r["request"].clone();
        if !e.is_null() {
            let j = unpack_group_entry(&e)?;
            verify(&e, field(&j["member"], "signing_key")?)?;
            if j["invitation"] != inv["id"]
                || j["app"] != self.config["app"]
                || j["group"] != self.config["group"]
                || e["signer"] != j["member"]["device"]
            {
                return Err(invalid());
            }
        }
        Ok(e)
    }
    fn invitation_grant(&self, inv: &Value) -> Result<Value> {
        let g = unpack_group_entry(&inv["grant"])?;
        grant(
            &inv["grant"],
            &inv["manager"],
            &json!({"app":self.config["app"],"group":self.config["group"],"revision":g["anchor_revision"]}),
        )?;
        if g["invitation"] != inv["id"]
            || g["expires"] != inv["expires"]
            || field(&g, "secret_hash")? != hash(field(inv, "secret")?.as_bytes())
            || field(&g, "delegate_key")?
                != hex::encode(
                    group_signing_key(field(inv, "delegate_secret")?)?
                        .verifying_key()
                        .as_bytes(),
                )
        {
            return Err(invalid());
        }
        Ok(g)
    }
    pub async fn join(&mut self, inv: &Value, name: &str) -> Result<()> {
        if number(inv, "version")? != 1
            || number(inv, "expires")? <= now()?
            || ["url", "app", "group"]
                .iter()
                .any(|k| inv[*k] != self.config[*k])
        {
            return Err(invalid());
        }
        let mode = inv.get("mode").and_then(Value::as_str).unwrap_or("manual");
        if mode != "manual" && mode != "auto" {
            return Err(invalid());
        }
        if mode == "auto" {
            self.invitation_grant(inv)?;
        }
        self.ensure_token()?;
        let j = json!({"version":1,"app":self.config["app"],"group":self.config["group"],"invitation":inv["id"],"member":member(&self.config,name)?,"token_hash":hash(field(&self.config,"token")?.as_bytes())});
        let e = if self.config["pending_join"]["invitation"]["id"] == inv["id"] {
            self.config["pending_join"]["request"].clone()
        } else {
            sign(
                &j,
                field(&self.config, "secret_key")?,
                field(&self.config, "device")?,
            )?
        };
        self.config["pending_join"] = json!({"invitation":inv,"request":e});
        self.call(
            reqwest::Method::POST,
            &format!("/enroll/{}", field(inv, "id")?),
            Some(&e),
            Some(format!("Invitation {}", field(inv, "secret")?)),
        )
        .await?;
        Ok(())
    }
    pub async fn finish_join(&mut self) -> Result<bool> {
        let p = self
            .config
            .get("pending_join")
            .cloned()
            .ok_or_else(invalid)?;
        let inv = &p["invitation"];
        let req = unpack_group_entry(&p["request"])?;
        if inv.get("mode").and_then(Value::as_str) == Some("auto") {
            return self.finish_auto(&p).await;
        }
        let r = self
            .call(
                reqwest::Method::GET,
                &format!("/enroll/{}", field(inv, "id")?),
                None,
                Some(format!("Claim {}", field(&self.config, "token")?)),
            )
            .await?;
        let e = &r["entry"];
        if e.is_null() {
            return Ok(false);
        }
        if e.get("authorization").is_some_and(|v| !v.is_null()) {
            return Err(invalid());
        }
        verify(e, field(&inv["manager"], "signing_key")?)?;
        let g = unpack_group_entry(e)?;
        validate_state(
            &g,
            field(&self.config, "app")?,
            field(&self.config, "group")?,
        )?;
        let own = members(&g)?
            .iter()
            .find(|m| m["device"] == self.config["device"])
            .ok_or_else(invalid)?;
        let mut expected = req["member"].clone();
        expected["manager"] = own["manager"].clone();
        if e["signer"] != inv["manager"]["device"]
            || g["invitation"] != inv["id"]
            || field(&g, "request_hash")? != hash(&raw(&p["request"])?)
            || *own != expected
        {
            return Err(invalid());
        }
        self.accept(e)?;
        self.remove_key("pending_join");
        Ok(true)
    }
    async fn finish_auto(&mut self, p: &Value) -> Result<bool> {
        let inv = &p["invitation"];
        let grant = self.invitation_grant(inv)?;
        let req = unpack_group_entry(&p["request"])?;
        let mut current: Option<Value> = None;
        let mut after = number(&grant, "anchor_revision")? - 1;
        let result = loop {
            let r = self
                .call(
                    reqwest::Method::GET,
                    &format!("/enroll/{}/auto?after={after}", field(inv, "id")?),
                    None,
                    Some(format!("Claim {}", field(&self.config, "token")?)),
                )
                .await?;
            let rev = number(&r, "revision")?;
            if rev < number(&grant, "anchor_revision")? || rev > 4096 {
                return Err(invalid());
            }
            let entries = r["entries"].as_array().ok_or_else(invalid)?;
            if entries.is_empty() {
                return Err(invalid());
            }
            for e in entries {
                if let Some(c) = &current {
                    advance_group(c, e)?;
                } else {
                    let state = unpack_group_entry(e)?;
                    if hash(&raw(e)?) != field(&grant, "anchor_hash")?
                        || number(&state, "revision")? != number(&grant, "anchor_revision")?
                    {
                        return Err(invalid());
                    }
                    validate_state(
                        &state,
                        field(&self.config, "app")?,
                        field(&self.config, "group")?,
                    )?;
                }
                current = Some(e.clone());
            }
            let revision = number(
                &unpack_group_entry(current.as_ref().ok_or_else(invalid)?)?,
                "revision",
            )?;
            if revision <= after || revision > rev {
                return Err(invalid());
            }
            after = revision;
            if after == rev {
                break r;
            }
        };
        let current = current.ok_or_else(invalid)?;
        let e = if !result["entry"].is_null() {
            if current != result["entry"] {
                return Err(invalid());
            }
            current
        } else {
            let mut g = unpack_group_entry(&current)?;
            g["members"]
                .as_array_mut()
                .ok_or_else(invalid)?
                .push(req["member"].clone());
            g["revision"] = json!(number(&g, "revision")? + 1);
            g["previous"] = json!(hash(&raw(&current)?));
            g["invitation"] = inv["id"].clone();
            g["request_hash"] = json!(hash(&raw(&p["request"])?));
            let mut e = sign(
                &g,
                field(inv, "delegate_secret")?,
                field(&inv["manager"], "device")?,
            )?;
            e["authorization"] = inv["grant"].clone();
            advance_group(&current, &e)?;
            self.config["pending_join"]["auto_entry"] = e.clone();
            let r = self
                .call(
                    reqwest::Method::POST,
                    &format!("/enroll/{}/auto", field(inv, "id")?),
                    Some(&e),
                    Some(format!("Claim {}", field(&self.config, "token")?)),
                )
                .await?;
            if r != e {
                return Err(invalid());
            }
            e
        };
        let g = unpack_group_entry(&e)?;
        let own = members(&g)?
            .iter()
            .find(|m| m["device"] == self.config["device"])
            .ok_or_else(invalid)?;
        if e["authorization"] != inv["grant"]
            || g["invitation"] != inv["id"]
            || field(&g, "request_hash")? != hash(&raw(&p["request"])?)
            || *own != req["member"]
        {
            return Err(invalid());
        }
        self.accept(&e)?;
        self.remove_key("pending_join");
        Ok(true)
    }
    async fn change(&mut self, mut g: Value) -> Result<()> {
        let old = self.config["group_entry"].clone();
        g["revision"] = json!(number(&g, "revision")? + 1);
        g["previous"] = json!(hash(&raw(&old)?));
        let e = sign(
            &g,
            field(&self.config, "secret_key")?,
            field(&self.config, "device")?,
        )?;
        advance_group(&old, &e)?;
        self.call(reqwest::Method::PUT, "/group", Some(&e), None)
            .await?;
        self.accept(&e)
    }
    pub async fn approve(&mut self, inv: &Value, request: &Value, manager: bool) -> Result<()> {
        self.refresh().await?;
        let j = unpack_group_entry(request)?;
        verify(request, field(&j["member"], "signing_key")?)?;
        if j["invitation"] != inv["id"]
            || j["app"] != self.config["app"]
            || j["group"] != self.config["group"]
        {
            return Err(invalid());
        }
        let mut g = unpack_group_entry(&self.config["group_entry"])?;
        let mut m = j["member"].clone();
        m["manager"] = json!(manager);
        let ms = g["members"].as_array_mut().ok_or_else(invalid)?;
        ms.retain(|v| v["device"] != m["device"]);
        ms.push(m);
        g["invitation"] = inv["id"].clone();
        g["request_hash"] = json!(hash(&raw(request)?));
        self.change(g).await
    }
    pub async fn remove(&mut self, device: &str) -> Result<()> {
        if field(&self.config, "device")? == device {
            return Err(invalid());
        }
        self.refresh().await?;
        let mut g = unpack_group_entry(&self.config["group_entry"])?;
        g["members"]
            .as_array_mut()
            .ok_or_else(invalid)?
            .retain(|m| m["device"] != device);
        g["invitation"] = json!("");
        g["request_hash"] = json!("");
        self.change(g).await
    }
    pub async fn rename(&mut self, device: &str, name: &str) -> Result<()> {
        let name = name.trim();
        if name.is_empty() || name.len() > 128 {
            return Err(invalid());
        }
        self.refresh().await?;
        let mut g = unpack_group_entry(&self.config["group_entry"])?;
        let m = g["members"]
            .as_array_mut()
            .ok_or_else(invalid)?
            .iter_mut()
            .find(|m| m["device"] == device)
            .ok_or_else(invalid)?;
        if m["name"] == name {
            return Ok(());
        }
        m["name"] = json!(name);
        g["invitation"] = json!("");
        g["request_hash"] = json!("");
        self.change(g).await
    }
    pub async fn prepare_exit(&mut self, disband: bool) -> Result<()> {
        if self
            .config
            .get("pending_exit")
            .is_some_and(|v| !v.is_null())
        {
            return Ok(());
        }
        self.refresh().await?;
        let old = self.config["group_entry"].clone();
        let mut g = unpack_group_entry(&old)?;
        let own = members(&g)?
            .iter()
            .find(|m| m["device"] == self.config["device"])
            .ok_or_else(invalid)?;
        if disband && !boolean(own, "manager") {
            return Err(invalid());
        }
        let ms = g["members"].as_array_mut().ok_or_else(invalid)?;
        if disband {
            ms.clear();
        } else {
            ms.retain(|m| m["device"] != self.config["device"]);
        }
        if ms.is_empty() {
            g["closed"] = json!(true);
        }
        g["invitation"] = json!("");
        g["request_hash"] = json!("");
        g["revision"] = json!(number(&g, "revision")? + 1);
        g["previous"] = json!(hash(&raw(&old)?));
        let e = sign(
            &g,
            field(&self.config, "secret_key")?,
            field(&self.config, "device")?,
        )?;
        advance_group(&old, &e)?;
        self.config["pending_exit"] = e;
        Ok(())
    }
    pub async fn exit(&mut self) -> Result<()> {
        let e = self
            .config
            .get("pending_exit")
            .cloned()
            .ok_or_else(invalid)?;
        if let Err(err) = self
            .call(reqwest::Method::POST, "/group/exit", Some(&e), None)
            .await
        {
            if err == Error::Relay("http 409".to_owned()) {
                self.remove_key("pending_exit");
            }
            return Err(err);
        }
        self.accept(&e)?;
        self.remove_key("pending_exit");
        Ok(())
    }
    /// Leave the group, persisting pending_exit before transmission.
    pub async fn leave(&mut self) -> Result<()> {
        self.prepare_exit(false).await?;
        self.exit().await
    }
    /// Disband a group as a manager.
    pub async fn disband(&mut self) -> Result<()> {
        self.prepare_exit(true).await?;
        self.exit().await
    }
    pub async fn cancel(&self, inv: &Value) -> Result<Value> {
        self.call(
            reqwest::Method::DELETE,
            &format!("/group/invitations/{}", field(inv, "id")?),
            None,
            None,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn group_vectors() {
        let v: Value =
            serde_json::from_str(include_str!("../../../protocol/group-vectors.json")).unwrap();
        verify(&v["initial"], field(&v["manager"], "signing_key").unwrap()).unwrap();
        verify(
            &v["request"],
            field(&v["new_member"], "signing_key").unwrap(),
        )
        .unwrap();
        assert_eq!(
            member(&v["config"], "Mac").unwrap()["signing_key"],
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
    #[tokio::test]
    async fn https_uses_bundled_tls_provider() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        let g = Groups::new(json!({"url":format!("wss://{address}/relay/v1/ws")}), false).unwrap();
        assert!(matches!(
            g.call(reqwest::Method::GET, "/group", None, None).await,
            Err(Error::Relay(_))
        ));
        task.abort();
    }
    #[tokio::test]
    async fn local_server_group_lifecycle() {
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
        let data = std::env::temp_dir().join(format!("relay-rust-group-{}", random(16).unwrap()));
        std::fs::create_dir(&data).unwrap();
        let credential = data.join("bootstrap.json");
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
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let _server = Server(proc, data);
        let mut ready = false;
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        }
        assert!(ready);
        let url = format!("ws://{addr}/relay/v1/ws");
        let config = |device: &str| json!({"url":url,"app":"example","device":device,"secret_key":random(32).unwrap(),"trusted_peers":{}});
        let mut initial = config("bootstrap-manager");
        initial["group"] = json!("bootstrap-test");
        let mut boot = Groups::new(initial, true).unwrap();
        boot.bootstrap(&code, "Bootstrap").await.unwrap();
        boot.refresh().await.unwrap();
        let mut a = Groups::new(config("creator"), true).unwrap();
        a.prepare_create("Devices", "Creator").unwrap();
        a.create().await.unwrap();
        let inv = a.invite("auto", true).await.unwrap();
        let mut c = config("phone");
        c["group"] = a.config["group"].clone();
        let mut b = Groups::new(c, true).unwrap();
        let resolved = b
            .resolve_invitation(inv["short_link"].as_str().unwrap())
            .await
            .unwrap();
        b.join(&resolved, "Phone").await.unwrap();
        assert!(b.finish_join().await.unwrap());
        a.refresh().await.unwrap();
        b.rename("phone", "Renamed").await.unwrap();
        a.refresh().await.unwrap();
        b.prepare_exit(false).await.unwrap();
        b.exit().await.unwrap();
        a.refresh().await.unwrap();
        a.prepare_exit(true).await.unwrap();
        a.exit().await.unwrap();
    }
    #[tokio::test]
    async fn http_does_not_follow_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = target.local_addr().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0; 4096];
            let _ = socket.read(&mut buf).await.unwrap();
            socket.write_all(format!("HTTP/1.1 302 Found\r\nLocation: http://{destination}/stolen\r\nContent-Length: 0\r\n\r\n").as_bytes()).await.unwrap();
        });
        let g = Groups::new(
            json!({"url":format!("ws://{addr}/relay/v1/ws"),"token":"test-only"}),
            true,
        )
        .unwrap();
        assert_eq!(
            g.call(reqwest::Method::GET, "/group", None, None)
                .await
                .unwrap_err(),
            Error::Relay("http 302".into())
        );
        task.await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), target.accept())
                .await
                .is_err()
        );
    }
}
