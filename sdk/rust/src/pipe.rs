//! `/v2/ws` message client: one connection lifetime. A reader task dispatches frames —
//! replies complete the matching request, application events queue for
//! [`Pipe::next_event`]. Reconnecting is the caller's job (see [`crate::policy::retry`]);
//! nothing is replayed implicitly.
//!
//! Application events (JSON objects):
//! - `{"type":"message","id","from","data":<base64>,"offline"}` — decrypted; acknowledge it
//!   with [`Pipe::acknowledge`] once handled so the relay stops redelivering it;
//! - `{"type":"undecryptable","id","from","offline","trusted"}` — an envelope this
//!   connection cannot open. If the sender is (now) a member, reconnect with fresh trusted
//!   keys and the relay redelivers it; otherwise acknowledge it to drop it for good. Failing
//!   the connection instead would make the relay redeliver it forever;
//! - `{"type":"peer.up"|"peer.down","device"}` and `{"type":"group.changed","revision"}`.
use crate::{
    access::{checked_access_password, valid_token, validate_endpoint},
    crypto::now,
    journal::Journal,
    new_message_id, Error, Identity, Options, Result, ACCESS_HEADER,
};
use futures_util::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue, Message};

const FRAME_LIMIT: usize = 270_336;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(45);
/// Lifetime of an offline message on the relay.
pub const OFFLINE_TTL: i64 = 86_400;

struct Shared {
    identity: Identity,
    journal: Option<Journal>,
    outgoing: mpsc::UnboundedSender<Message>,
    pending: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    events: mpsc::UnboundedSender<Value>,
    closed: AtomicBool,
    error: Mutex<Option<Error>>,
}

/// A connected `/v2/ws` session for one device in one group (space).
pub struct Pipe {
    shared: Arc<Shared>,
    events: AsyncMutex<mpsc::UnboundedReceiver<Value>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Shared {
    fn scope(&self) -> String {
        format!(
            "{}/{}/{}",
            self.identity.app, self.identity.group, self.identity.device
        )
    }

    fn fail(&self, error: Error) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        if let Ok(mut slot) = self.error.lock() {
            slot.get_or_insert(error);
        }
        if let Ok(mut pending) = self.pending.lock() {
            pending.clear(); // Dropping the senders wakes every waiter.
        }
        let _ = self.outgoing.send(Message::Close(None));
    }

    fn closed_error(&self) -> Error {
        self.error
            .lock()
            .ok()
            .and_then(|e| e.clone())
            .unwrap_or(Error::Connection("connection closed"))
    }

    fn send(&self, frame: Value) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(self.closed_error());
        }
        let text = frame.to_string();
        if text.len() > FRAME_LIMIT {
            return Err(Error::Invalid("frame too large"));
        }
        self.outgoing
            .send(Message::Text(text.into()))
            .map_err(|_| Error::Connection("connection closed"))
    }

    async fn request(&self, mut frame: Value) -> Result<Value> {
        let id = match frame["id"].as_str() {
            Some(id) => id.to_owned(),
            None => new_message_id()?,
        };
        frame["id"] = json!(id);
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self
                .pending
                .lock()
                .map_err(|_| Error::Connection("closed"))?;
            if pending.contains_key(&id) {
                return Err(Error::Invalid("request already pending"));
            }
            pending.insert(id.clone(), tx);
        }
        let result = match self.send(frame) {
            Err(e) => Err(e),
            Ok(()) => match tokio::time::timeout(REQUEST_TIMEOUT, rx).await {
                Ok(Ok(reply)) if reply["type"] == "error" => Err(Error::Relay(
                    reply["code"].as_str().unwrap_or("error").to_owned(),
                )),
                Ok(Ok(reply)) => Ok(reply),
                Ok(Err(_)) => Err(self.closed_error()),
                Err(_) => Err(Error::Timeout),
            },
        };
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&id);
        }
        result
    }

    /// v2 wire events to the SDK event shapes.
    fn translate(&self, v: Value) -> Value {
        match v["type"].as_str() {
            Some("presence") => {
                let devices: Vec<Value> = v["peers"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(
                        |d| json!({"app":self.identity.app,"group":self.identity.group,"device":d}),
                    )
                    .collect();
                json!({"type":"peers","id":v["id"],"devices":devices})
            }
            Some("msg") => {
                json!({"type":"message","id":v["id"],"from":v["from"],"body":v["body"],"offline":v["offline"].as_bool().unwrap_or(false)})
            }
            Some("ack") => json!({"type":v["event"].as_str().unwrap_or("stored"),"id":v["id"]}),
            Some("group.changed") => {
                json!({"type":"group.changed","revision":v["seq"].as_u64().unwrap_or(0)})
            }
            _ => v,
        }
    }

    fn dispatch(&self, raw: Value) -> Result<()> {
        let mut event = self.translate(raw);
        let kind = event["type"].as_str().unwrap_or("").to_owned();
        let id = event["id"].as_str().unwrap_or("").to_owned();
        if kind != "message" && kind != "stream.open" {
            let waiter = self
                .pending
                .lock()
                .map_err(|_| Error::Connection("closed"))?
                .remove(&id);
            if let Some(waiter) = waiter {
                let _ = waiter.send(event);
                return Ok(());
            }
        }
        if kind == "message" {
            let offline = event["offline"] == true;
            if offline && self.journal.is_none() {
                return Err(Error::Invalid("offline messages need a journal"));
            }
            let from = event["from"]
                .as_str()
                .ok_or(Error::Protocol("message without sender"))?
                .to_owned();
            let body = event["body"].as_str().unwrap_or("");
            let (data, expires) = match self.identity.open_message_parts(&from, &id, body) {
                Ok(parts) => parts,
                Err(_) => {
                    let trusted = self.identity.trusts(&from);
                    let _ = self.events.send(json!({"type":"undecryptable","id":id,"from":from,"offline":offline,"trusted":trusted}));
                    return Ok(());
                }
            };
            let replay = match &self.journal {
                Some(journal) => journal.contains(&self.scope(), &from, &id)?,
                None => false,
            };
            if expires.is_some_and(|e| e <= now()) || replay {
                if offline {
                    self.send(
                        json!({"type":"ack","space":self.identity.group,"id":id,"from":from}),
                    )?;
                }
                return Ok(());
            }
            event["data"] = json!(base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                data
            ));
            if let Some(o) = event.as_object_mut() {
                o.remove("body");
            }
        }
        if kind == "received" && !id.is_empty() {
            if let Some(journal) = &self.journal {
                let _ = journal.complete(&self.scope(), &id);
            }
        }
        if matches!(
            kind.as_str(),
            "message" | "received" | "peer.up" | "peer.down" | "group.changed"
        ) {
            let _ = self.events.send(event);
        }
        Ok(())
    }
}

impl Pipe {
    /// Connects `url` (`wss://host/v2/ws`) with the device `token` and waits for the relay's
    /// `hello` for this identity. `journal` is required to send or receive offline messages.
    pub async fn connect(
        url: &str,
        token: &str,
        options: &Options,
        identity: Identity,
        journal: Option<Journal>,
    ) -> Result<Self> {
        let endpoint = validate_endpoint(url, options)
            .ok_or(Error::Invalid("relay URL must be wss://host/v2/ws"))?;
        if !valid_token(token) {
            return Err(Error::Invalid("invalid device token"));
        }
        let password = checked_access_password(options.password.as_deref())?;
        let mut request = endpoint
            .as_str()
            .into_client_request()
            .map_err(|_| Error::Invalid("relay URL"))?;
        let headers = request.headers_mut();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| Error::Invalid("token"))?,
        );
        if let Some(password) = password {
            headers.insert(
                ACCESS_HEADER,
                HeaderValue::from_str(password).map_err(|_| Error::Invalid("password"))?,
            );
        }
        let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
            .max_message_size(Some(FRAME_LIMIT))
            .max_frame_size(Some(FRAME_LIMIT));
        let connect = tokio_tungstenite::connect_async_with_config(request, Some(config), false);
        let (mut socket, _) = match tokio::time::timeout(Duration::from_secs(15), connect).await {
            Err(_) => return Err(Error::Timeout),
            Ok(Err(tokio_tungstenite::tungstenite::Error::Http(response))) => {
                return Err(Error::Http(response.status().as_u16()))
            }
            Ok(Err(_)) => return Err(Error::Connection("connection failed")),
            Ok(Ok(pair)) => pair,
        };
        let greeting: Value = loop {
            let next = tokio::time::timeout(Duration::from_secs(15), socket.next())
                .await
                .map_err(|_| Error::Timeout)?;
            match next {
                Some(Ok(Message::Text(t))) => {
                    break serde_json::from_str(&t)
                        .map_err(|_| Error::Protocol("invalid greeting"))?
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                _ => return Err(Error::Connection("connection closed before hello")),
            }
        };
        let device = greeting["from"]
            .as_str()
            .or_else(|| greeting["device"].as_str());
        if greeting["type"] != "hello" || device != Some(identity.device()) {
            return Err(Error::Protocol("relay identity mismatch"));
        }
        let (mut sink, mut stream) = socket.split();
        let (outgoing, mut outgoing_rx) = mpsc::unbounded_channel::<Message>();
        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            identity,
            journal,
            outgoing,
            pending: Mutex::new(HashMap::new()),
            events: events_tx,
            closed: AtomicBool::new(false),
            error: Mutex::new(None),
        });
        let writer_state = shared.clone();
        let writer = tokio::spawn(async move {
            while let Some(message) = outgoing_rx.recv().await {
                let close = matches!(message, Message::Close(_));
                if sink.send(message).await.is_err() {
                    writer_state.fail(Error::Connection("connection closed"));
                    break;
                }
                if close {
                    break;
                }
            }
            let _ = sink.close().await;
        });
        let reader_state = shared.clone();
        let reader = tokio::spawn(async move {
            let mut cleaned = tokio::time::Instant::now();
            while let Some(frame) = stream.next().await {
                let outcome = match frame {
                    Ok(Message::Text(t)) => serde_json::from_str::<Value>(&t)
                        .map_err(|_| Error::Protocol("invalid frame"))
                        .and_then(|v| reader_state.dispatch(v)),
                    Ok(Message::Close(_)) => Err(Error::Connection("connection closed")),
                    Ok(_) => Ok(()), // Pings are answered by tungstenite; binary streams are not used.
                    Err(_) => Err(Error::Connection("connection lost")),
                };
                if let Err(e) = outcome {
                    reader_state.fail(e);
                    return;
                }
                if cleaned.elapsed() > Duration::from_secs(3600) {
                    cleaned = tokio::time::Instant::now();
                    if let Some(journal) = &reader_state.journal {
                        let _ = journal.cleanup();
                    }
                }
            }
            reader_state.fail(Error::Connection("connection closed"));
        });
        Ok(Pipe {
            shared,
            events: AsyncMutex::new(events_rx),
            tasks: vec![writer, reader],
        })
    }

    pub fn identity(&self) -> &Identity {
        &self.shared.identity
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::SeqCst)
    }

    /// Next application event; `Ok(None)` after `timeout`; `Err` once the connection closed.
    pub async fn next_event(&self, timeout: Duration) -> Result<Option<Value>> {
        let mut events = self.events.lock().await;
        match tokio::time::timeout(timeout, events.recv()).await {
            Ok(Some(event)) => Ok(Some(event)),
            Ok(None) => Err(self.shared.closed_error()),
            Err(_) if self.is_closed() => Err(self.shared.closed_error()),
            Err(_) => Ok(None),
        }
    }

    /// Online devices of this space: `{"type":"peers","devices":[{app,group,device}]}`.
    pub async fn peers(&self) -> Result<Value> {
        self.shared
            .request(json!({"type":"presence","space":self.shared.identity.group}))
            .await
    }

    /// Sends `data` to `to` and waits for the relay's acknowledgement (`stored`, `forwarded`
    /// or `received`). Offline messages are journaled first so retrying with the same `id`
    /// resends the same sealed bytes; save the id before calling.
    pub async fn message(
        &self,
        to: &str,
        data: &[u8],
        offline: bool,
        id: Option<&str>,
    ) -> Result<Value> {
        let shared = &self.shared;
        let id = match id {
            Some(id) => id.to_owned(),
            None => new_message_id()?,
        };
        let (body, expires) = if offline {
            let journal = shared
                .journal
                .as_ref()
                .ok_or(Error::Invalid("offline messages need a journal"))?;
            let row = journal.prepare(&shared.scope(), &id, to, data, OFFLINE_TTL, |expires| {
                shared
                    .identity
                    .seal_message_expiring(to, &id, data, expires)
            })?;
            if row["status"] == "received" {
                return Ok(json!({"type":"received","id":id}));
            }
            (
                row["body"].as_str().unwrap_or("").to_owned(),
                row["expires"].as_i64().unwrap_or(0),
            )
        } else {
            (shared.identity.seal_message(to, &id, data)?, 0)
        };
        let mut frame = json!({"type":"msg","space":shared.identity.group,"id":id,"to":to,"body":body,"offline":offline});
        if offline {
            frame["ttl"] = json!((expires - now()).clamp(1, OFFLINE_TTL));
        }
        let reply = shared.request(frame).await?;
        if offline && reply["type"] == "received" {
            if let Some(journal) = &shared.journal {
                journal.complete(&shared.scope(), &id)?;
            }
        }
        Ok(reply)
    }

    /// Marks a message handled (future replays are dropped) and acknowledges it so the relay
    /// deletes the stored copy. Also used to drop an `undecryptable` message.
    pub fn acknowledge(&self, from: &str, id: &str, offline: bool) -> Result<()> {
        let shared = &self.shared;
        if offline && shared.journal.is_none() {
            return Err(Error::Invalid("offline messages need a journal"));
        }
        if let Some(journal) = &shared.journal {
            journal.acknowledge(&shared.scope(), from, id)?;
        }
        // v2 relays answer an ack only to the original sender (`received`).
        shared.send(json!({"type":"ack","space":shared.identity.group,"id":id,"from":from}))
    }

    pub fn close(&self) {
        self.shared.fail(Error::Connection("closed by client"));
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        self.close();
        for task in &self.tasks {
            task.abort();
        }
    }
}
