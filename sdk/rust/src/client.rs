use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Deserializer, Serialize};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use url::Url;

use crate::crypto::{now, random, valid_id, valid_key, valid_name};
use crate::journal::{Prepared, RelayJournal, DEFAULT_TTL};
use crate::secretstream::{DecryptStream, EncryptStream, ABYTES};
use crate::stream::{RelayStream, StreamShared};
use crate::{Error, Identity, Result};

const LIMIT: Duration = Duration::from_secs(45);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);
const MAX_STREAMS: usize = 256;
const QUEUE: usize = 64;
const SUBPROTOCOL: &str = "common-relay.v1";

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Untrusted discovery information, never an update to the identity's pinned keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub app: String,
    pub group: String,
    pub device: String,
    pub public_key: String,
}

fn null_default<'de, D: Deserializer<'de>, T: Default + Deserialize<'de>>(
    d: D,
) -> std::result::Result<T, D::Error> {
    Ok(Option::deserialize(d)?.unwrap_or_default())
}
fn is_zero(value: &i64) -> bool {
    *value == 0
}
fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    #[serde(rename = "type", default, deserialize_with = "null_default")]
    pub kind: String,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub id: String,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub from: String,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub to: String,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub body: String,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "std::ops::Not::not"
    )]
    pub offline: bool,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub code: String,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "is_zero"
    )]
    pub version: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<Peer>,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub devices: Vec<Peer>,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "is_zero"
    )]
    pub revision: i64,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "String::is_empty"
    )]
    pub device: String,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "is_zero_u64"
    )]
    pub sequence: u64,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "is_zero"
    )]
    pub ttl: i64,
    #[serde(
        default,
        deserialize_with = "null_default",
        skip_serializing_if = "is_zero"
    )]
    pub expires: i64,
    /// Authenticated plaintext, only populated for messages.
    #[serde(skip)]
    pub data: Vec<u8>,
}

impl Event {
    pub(crate) fn request(kind: &str, id: String) -> Self {
        Self {
            kind: kind.into(),
            id,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    pub allow_local_test: bool,
}

struct Pending {
    expected: &'static [&'static str],
    reply: oneshot::Sender<Result<Event>>,
}

#[derive(Default)]
struct State {
    failure: Option<Error>,
    pending: HashMap<String, Pending>,
    streams: HashMap<String, Arc<StreamShared>>,
}

pub(crate) struct Shared {
    state: Mutex<State>,
    closed: watch::Sender<bool>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// Records the first failure, rejects pending requests, interrupts streams and stops the connection task.
    fn fail(&self, err: Error) {
        let (pending, streams) = {
            let mut state = self.lock();
            if state.failure.is_some() {
                return;
            }
            state.failure = Some(err);
            (
                std::mem::take(&mut state.pending),
                std::mem::take(&mut state.streams),
            )
        };
        drop(pending);
        for stream in streams.values() {
            stream.abort();
        }
        self.closed.send_replace(true);
    }
    fn check(&self) -> Result<()> {
        self.lock().failure.clone().map_or(Ok(()), Err)
    }
    fn err(&self) -> Error {
        self.lock()
            .failure
            .clone()
            .unwrap_or(Error::Connection("client closed"))
    }
}

struct Outbound {
    message: Message,
    written: Option<oneshot::Sender<Result<()>>>,
}

/// The connection handle shared by the client and its streams.
#[derive(Clone)]
pub(crate) struct Link {
    shared: Arc<Shared>,
    outbound: mpsc::Sender<Outbound>,
}

impl Link {
    async fn send_message(&self, message: Message) -> Result<()> {
        self.shared.check()?;
        let (written, result) = oneshot::channel();
        let command = Outbound {
            message,
            written: Some(written),
        };
        if self.outbound.send(command).await.is_err() {
            return Err(self.shared.err());
        }
        result.await.unwrap_or_else(|_| Err(self.shared.err()))
    }

    pub(crate) async fn send_event(&self, event: &Event) -> Result<()> {
        let text = serde_json::to_string(event).expect("event JSON");
        self.send_message(Message::text(text)).await
    }

    pub(crate) async fn send_frame(&self, frame: Vec<u8>) -> Result<()> {
        self.send_message(Message::binary(frame)).await
    }

    /// Best effort from synchronous contexts such as `Drop`.
    pub(crate) fn try_send_event(&self, event: &Event) {
        if self.shared.check().is_ok() {
            let text = serde_json::to_string(event).expect("event JSON");
            let _ = self.outbound.try_send(Outbound {
                message: Message::text(text),
                written: None,
            });
        }
    }

    pub(crate) fn is_failed(&self) -> bool {
        self.shared.check().is_err()
    }

    fn register_stream(&self, id: &str, stream: Arc<StreamShared>) -> Result<()> {
        let mut state = self.shared.lock();
        if let Some(err) = &state.failure {
            return Err(err.clone());
        }
        if state.streams.len() >= MAX_STREAMS {
            return Err(Error::Invalid("too many open streams"));
        }
        if state.streams.contains_key(id) {
            return Err(Error::Invalid("duplicate stream ID"));
        }
        state.streams.insert(id.into(), stream);
        Ok(())
    }

    pub(crate) fn remove_stream(&self, id: &str) {
        let stream = self.shared.lock().streams.remove(id);
        if let Some(stream) = stream {
            stream.abort();
        }
    }

    async fn request(&self, event: Event, expected: &'static [&'static str]) -> Result<Event> {
        let (reply, result) = oneshot::channel();
        {
            let mut state = self.shared.lock();
            if let Some(err) = &state.failure {
                return Err(err.clone());
            }
            if state.pending.len() >= QUEUE {
                return Err(Error::Invalid("too many pending requests"));
            }
            if state.pending.contains_key(&event.id) {
                return Err(Error::Invalid("request already pending"));
            }
            state
                .pending
                .insert(event.id.clone(), Pending { expected, reply });
        }
        let _guard = PendingGuard {
            shared: &self.shared,
            id: event.id.clone(),
        };
        let exchange = async {
            self.send_event(&event).await?;
            result.await.unwrap_or_else(|_| Err(self.shared.err()))
        };
        timeout(LIMIT, exchange).await.map_err(|_| Error::Timeout)?
    }
}

/// Removes a request's reply slot however its caller finishes, including cancellation.
struct PendingGuard<'a> {
    shared: &'a Shared,
    id: String,
}
impl Drop for PendingGuard<'_> {
    fn drop(&mut self) {
        self.shared.lock().pending.remove(&self.id);
    }
}

/// Owns one connection. Reconnect explicitly; online messages are never replayed.
pub struct Client {
    identity: Arc<Identity>,
    link: Link,
    events: tokio::sync::Mutex<mpsc::Receiver<Event>>,
    journal: Option<Arc<RelayJournal>>,
    scope: String,
}

fn new_id() -> Result<String> {
    Ok(hex::encode(random::<16>()?))
}

pub(crate) fn validate_endpoint(endpoint: &str, options: Options) -> Option<Url> {
    let u = Url::parse(endpoint).ok()?;
    let local = options.allow_local_test && u.scheme() == "ws" && u.host_str() == Some("127.0.0.1");
    let valid = (u.scheme() == "wss" || local)
        && u.host_str().is_some_and(|h| !h.is_empty())
        && u.username().is_empty()
        && u.password().is_none()
        && u.query().is_none()
        && u.fragment().is_none()
        && u.path() == "/relay/v1/ws";
    valid.then_some(u)
}

pub(crate) fn valid_token(token: &str) -> bool {
    (32..=256).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

async fn read_welcome(socket: &mut Socket) -> Result<Event> {
    loop {
        match socket.next().await {
            Some(Ok(Message::Text(text))) => {
                return serde_json::from_str(text.as_str())
                    .map_err(|_| Error::Protocol("invalid welcome"));
            }
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
            Some(Ok(_)) => return Err(Error::Protocol("invalid welcome")),
            Some(Err(_)) | None => return Err(Error::Connection("welcome read failed")),
        }
    }
}

impl Client {
    /// The 45 second limit covers the handshake. `close` or drop owns the connection lifetime.
    /// Without a journal, offline sends fail and an offline delivery closes the connection.
    pub async fn connect(
        endpoint: &str,
        token: &str,
        identity: Arc<Identity>,
        options: Options,
    ) -> Result<Self> {
        Self::open(endpoint, token, identity, options, None).await
    }

    /// Connects with a persistent journal, enabling offline sends, acknowledgements and dedupe.
    /// Reuse the same journal for reconnects; it is cleaned hourly while connected.
    pub async fn connect_with_journal(
        endpoint: &str,
        token: &str,
        identity: Arc<Identity>,
        options: Options,
        journal: Arc<RelayJournal>,
    ) -> Result<Self> {
        Self::open(endpoint, token, identity, options, Some(journal)).await
    }

    async fn open(
        endpoint: &str,
        token: &str,
        identity: Arc<Identity>,
        options: Options,
        journal: Option<Arc<RelayJournal>>,
    ) -> Result<Self> {
        let url = validate_endpoint(endpoint, options).ok_or(Error::Invalid(
            "a WSS relay endpoint and identity are required",
        ))?;
        if !valid_token(token) {
            return Err(Error::Invalid("invalid device credential"));
        }
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|_| Error::Invalid("invalid relay endpoint"))?;
        let headers = request.headers_mut();
        headers.insert(
            "Authorization",
            HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| Error::Invalid("invalid device credential"))?,
        );
        headers.insert(
            "Sec-WebSocket-Protocol",
            HeaderValue::from_static(SUBPROTOCOL),
        );
        let config = WebSocketConfig::default()
            .max_message_size(Some(1 << 20))
            .max_frame_size(Some(1 << 20));
        let handshake = async {
            // tungstenite never follows redirects, so the credential only reaches this endpoint.
            let (mut socket, response) =
                tokio_tungstenite::connect_async_with_config(request, Some(config), true)
                    .await
                    .map_err(|_| Error::Connection("relay handshake failed"))?;
            if response
                .headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|v| v.to_str().ok())
                != Some(SUBPROTOCOL)
            {
                return Err(Error::Protocol("protocol mismatch"));
            }
            let welcome = read_welcome(&mut socket).await?;
            Ok((socket, welcome))
        };
        let (socket, welcome) = timeout(LIMIT, handshake)
            .await
            .map_err(|_| Error::Timeout)??;
        let own = match welcome.identity {
            Some(own) if welcome.kind == "welcome" && welcome.version == 1 => own,
            _ => return Err(Error::Protocol("invalid welcome")),
        };
        if own.app != identity.app
            || own.group != identity.group
            || own.device != identity.device
            || own.public_key != identity.public_key()
        {
            return Err(Error::Protocol("welcome identity mismatch"));
        }
        let shared = Arc::new(Shared {
            state: Mutex::new(State::default()),
            closed: watch::channel(false).0,
        });
        let (outbound, commands) = mpsc::channel(QUEUE);
        let (events_tx, events) = mpsc::channel(QUEUE);
        let scope = serde_json::to_string(&[&identity.app, &identity.group, &identity.device])
            .expect("JSON value");
        let link = Link { shared, outbound };
        let task = Connection {
            socket,
            identity: identity.clone(),
            link: link.clone(),
            events: events_tx,
            journal: journal.clone(),
            scope: scope.clone(),
        };
        tokio::spawn(task.run(commands));
        if let Some(journal) = journal.clone() {
            tokio::spawn(clean_periodically(journal, link.shared.clone()));
        }
        Ok(Self {
            identity,
            link,
            events: tokio::sync::Mutex::new(events),
            journal,
            scope,
        })
    }

    pub fn close(&self) {
        self.link.shared.fail(Error::Connection("client closed"));
    }

    #[cfg(test)]
    pub(crate) fn pending_count(&self) -> usize {
        self.link.shared.lock().pending.len()
    }

    /// The failure that ended the connection, if any.
    pub fn err(&self) -> Option<Error> {
        self.link.shared.lock().failure.clone()
    }

    async fn request(&self, event: Event, expected: &'static [&'static str]) -> Result<Event> {
        self.link.request(event, expected).await
    }

    pub async fn peers(&self) -> Result<Vec<Peer>> {
        let event = self
            .request(Event::request("peers", new_id()?), &["peers"])
            .await?;
        for p in &event.devices {
            if p.app != self.identity.app
                || p.group != self.identity.group
                || !valid_name(&p.device)
                || !valid_key(&p.public_key)
            {
                return Err(Error::Protocol("invalid peer scope"));
            }
        }
        Ok(event.devices)
    }

    /// Sends online-only data. `forwarded` is a relay queue receipt, not peer delivery.
    /// Dropping the future stops waiting but cannot undo a message already sent.
    pub async fn message(&self, to: &str, data: &[u8]) -> Result<Event> {
        let id = new_id()?;
        let body = self.identity.seal_message(to, &id, data)?;
        let event = Event {
            to: to.into(),
            body,
            ..Event::request("message", id)
        };
        self.request(event, &["forwarded"]).await
    }

    /// Sends a durable offline message valid for 24 hours. Save `id` (see
    /// [`crate::new_message_id`]) before calling and retry with the same ID and data: the
    /// original ciphertext and absolute expiry are reused, never renewed. Returns `stored`
    /// (relay saved it) or `received` (recipient acknowledged). Requires a journal.
    pub async fn message_offline(&self, to: &str, id: &str, data: &[u8]) -> Result<Event> {
        let journal = self.journal.as_ref().ok_or(Error::Invalid(
            "offline delivery requires a persistent journal",
        ))?;
        if !valid_id(id) {
            return Err(Error::Invalid("invalid message ID"));
        }
        let prepared = journal.prepare(&self.scope, id, to, data, DEFAULT_TTL, |expires| {
            self.identity.seal_offline_message(to, id, data, expires)
        })?;
        let (body, expires) = match prepared {
            Prepared::Received => {
                return Ok(Event::request("received", id.into()));
            }
            Prepared::Send { body, expires } => (body, expires),
        };
        let event = Event {
            to: to.into(),
            body,
            offline: true,
            ttl: (expires - now()).max(1),
            expires,
            ..Event::request("message", id.into())
        };
        let result = self.request(event, &["stored", "received"]).await?;
        if result.kind == "received" {
            journal.complete(&self.scope, id)?;
        }
        Ok(result)
    }

    /// Call only after the application durably handled `event`. The dedupe record is saved
    /// before the ACK, so a redelivery after a lost ACK is re-acknowledged, not redelivered.
    pub async fn acknowledge(&self, event: &Event) -> Result<()> {
        if event.kind != "message" || !valid_id(&event.id) || !valid_name(&event.from) {
            return Err(Error::Invalid("only received messages can be acknowledged"));
        }
        match &self.journal {
            Some(journal) => journal.acknowledge(&self.scope, &event.from, &event.id)?,
            None if event.offline => {
                return Err(Error::Invalid(
                    "offline acknowledgement requires a persistent journal",
                ))
            }
            None => {}
        }
        if event.offline {
            let ack = Event {
                from: event.from.clone(),
                ..Event::request("ack", event.id.clone())
            };
            self.request(ack, &["acked"]).await?;
        }
        Ok(())
    }

    /// Runs one bounded journal cleanup round (at most 256 changes). No-op without a journal.
    pub fn cleanup(&self) -> Result<usize> {
        self.journal.as_ref().map_or(Ok(0), |j| j.cleanup())
    }

    /// Opens an encrypted bidirectional stream; resolves once the peer accepts.
    pub async fn open_stream(&self, to: &str) -> Result<RelayStream> {
        let id = new_id()?;
        let encryptor = EncryptStream::new()?;
        let body = self
            .identity
            .seal_value(to, "stream.open", &id, encryptor.descriptor())?;
        let (shared, incoming) = StreamShared::new();
        self.link.register_stream(&id, shared.clone())?;
        let opened = async {
            let event = Event {
                to: to.into(),
                body,
                ..Event::request("stream.open", id.clone())
            };
            let reply = self.request(event, &["stream.accept"]).await?;
            let descriptor = self
                .identity
                .open_value(to, "stream.accept", &id, &reply.body)?;
            DecryptStream::new(&descriptor)
        };
        match opened.await {
            Ok(decryptor) => Ok(RelayStream::new(
                id,
                to.into(),
                self.identity.clone(),
                self.link.clone(),
                shared,
                incoming,
                encryptor,
                decryptor,
            )),
            Err(err) => {
                self.link.remove_stream(&id);
                self.link
                    .try_send_event(&Event::request("stream.close", id.clone()));
                Err(err)
            }
        }
    }

    /// Accepts a `stream.open` event delivered by [`Client::next_event`].
    pub async fn accept_stream(&self, event: &Event) -> Result<RelayStream> {
        if event.kind != "stream.open" || !valid_name(&event.from) {
            return Err(Error::Invalid("not a stream request"));
        }
        let descriptor =
            self.identity
                .open_value(&event.from, "stream.open", &event.id, &event.body)?;
        let decryptor = DecryptStream::new(&descriptor)?;
        let encryptor = EncryptStream::new()?;
        let body = self.identity.seal_value(
            &event.from,
            "stream.accept",
            &event.id,
            encryptor.descriptor(),
        )?;
        let (shared, incoming) = StreamShared::new();
        self.link.register_stream(&event.id, shared.clone())?;
        let accept = Event {
            body,
            ..Event::request("stream.accept", event.id.clone())
        };
        if let Err(err) = self.request(accept, &["stream.ready"]).await {
            self.link.remove_stream(&event.id);
            return Err(err);
        }
        Ok(RelayStream::new(
            event.id.clone(),
            event.from.clone(),
            self.identity.clone(),
            self.link.clone(),
            shared,
            incoming,
            encryptor,
            decryptor,
        ))
    }

    /// Declines a `stream.open` request.
    pub async fn reject_stream(&self, event: &Event) -> Result<()> {
        if event.kind != "stream.open" || !valid_id(&event.id) {
            return Err(Error::Invalid("not a stream request"));
        }
        self.link
            .send_event(&Event::request("stream.close", event.id.clone()))
            .await
    }

    /// Receives authenticated messages, stream requests or untrusted presence/change notifications.
    /// Queue capacity is 64; a slow consumer closes the connection rather than losing data.
    pub async fn next_event(&self) -> Result<Event> {
        let shared = &self.link.shared;
        shared.check()?;
        let mut closed = shared.closed.subscribe();
        let mut events = self.events.lock().await;
        tokio::select! {
            event = events.recv() => {
                shared.check()?;
                event.ok_or_else(|| shared.err())
            }
            _ = closed_signal(&mut closed) => Err(shared.err()),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.close();
    }
}

async fn clean_periodically(journal: Arc<RelayJournal>, shared: Arc<Shared>) {
    let mut closed = shared.closed.subscribe();
    loop {
        tokio::select! {
            _ = closed_signal(&mut closed) => return,
            _ = tokio::time::sleep(CLEANUP_INTERVAL) => {
                // Never keep running when durable state can no longer be maintained.
                if let Err(err) = journal.cleanup() {
                    shared.fail(err);
                    return;
                }
            }
        }
    }
}

struct Connection {
    socket: Socket,
    identity: Arc<Identity>,
    link: Link,
    events: mpsc::Sender<Event>,
    journal: Option<Arc<RelayJournal>>,
    scope: String,
}

impl Connection {
    async fn run(mut self, mut commands: mpsc::Receiver<Outbound>) {
        let shared = self.link.shared.clone();
        let mut closed = shared.closed.subscribe();
        let result = loop {
            tokio::select! {
                _ = closed_signal(&mut closed) => break Ok(()),
                command = commands.recv() => {
                    let Some(command) = command else { break Ok(()) };
                    let result = self.write(command.message).await;
                    if let Some(written) = command.written {
                        let _ = written.send(result.clone());
                    }
                    if let Err(err) = result {
                        break Err(err);
                    }
                }
                frame = self.socket.next() => {
                    if let Err(err) = self.receive(frame).await {
                        break Err(err);
                    }
                }
            }
        };
        if let Err(err) = result {
            shared.fail(err);
        }
        // Dropping the socket closes the connection without a close handshake.
    }

    async fn write(&mut self, message: Message) -> Result<()> {
        match timeout(LIMIT, self.socket.send(message)).await {
            Ok(Ok(())) => Ok(()),
            _ => Err(Error::Connection("relay write failed")),
        }
    }

    async fn write_event(&mut self, event: &Event) -> Result<()> {
        self.write(Message::text(
            serde_json::to_string(event).expect("event JSON"),
        ))
        .await
    }

    fn stream(&self, id: &str) -> Option<Arc<StreamShared>> {
        self.link.shared.lock().streams.get(id).cloned()
    }

    async fn receive_frame(&mut self, data: &[u8]) -> Result<()> {
        if !(25 + ABYTES..=25 + 65536).contains(&data.len()) || data[0] != 1 {
            return Err(Error::Protocol("invalid stream frame"));
        }
        let id = hex::encode(&data[1..17]);
        let sequence = u64::from_be_bytes(data[17..25].try_into().expect("sequence"));
        // Frames for streams closed locally are dropped.
        if let Some(stream) = self.stream(&id) {
            if !stream.deliver(sequence, data[25..].to_vec()) {
                self.link.remove_stream(&id);
                self.write_event(&Event::request("stream.close", id))
                    .await?;
            }
        }
        Ok(())
    }

    async fn receive(
        &mut self,
        frame: Option<std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>,
    ) -> Result<()> {
        let text = match frame {
            Some(Ok(Message::Text(text))) => text,
            Some(Ok(Message::Binary(data))) => return self.receive_frame(&data).await,
            Some(Ok(Message::Ping(_) | Message::Pong(_))) => return Ok(()),
            Some(Ok(Message::Frame(_))) => return Err(Error::Protocol("invalid relay frame")),
            Some(Ok(Message::Close(_)) | Err(_)) | None => {
                return Err(Error::Connection("relay connection closed"))
            }
        };
        let mut event: Event = serde_json::from_str(text.as_str())
            .map_err(|_| Error::Protocol("invalid relay frame"))?;
        match event.kind.as_str() {
            "welcome" => return Err(Error::Protocol("repeated welcome")),
            "stream.credit" => {
                if let Some(stream) = self.stream(&event.id) {
                    stream.credit(event.sequence)?;
                }
                return Ok(());
            }
            "stream.close" => {
                self.link.remove_stream(&event.id);
                let pending = self.link.shared.lock().pending.remove(&event.id);
                if let Some(p) = pending {
                    let code = if event.code.is_empty() {
                        "stream_closed".into()
                    } else {
                        event.code
                    };
                    let _ = p.reply.send(Err(Error::Relay(code)));
                }
                return Ok(());
            }
            "stream.open" => {
                if !valid_id(&event.id) || !valid_name(&event.from) {
                    return Err(Error::Protocol("invalid stream request"));
                }
            }
            "message" => {
                if event.offline && self.journal.is_none() {
                    return Err(Error::Protocol(
                        "offline reception requires a persistent SDK",
                    ));
                }
                let (data, expires) =
                    self.identity
                        .open_message_parts(&event.from, &event.id, &event.body)?;
                let seen = match &self.journal {
                    Some(journal) => journal.contains(&self.scope, &event.from, &event.id)?,
                    None => false,
                };
                if seen || expires.is_some_and(|expiry| expiry <= now()) {
                    // Already handled (lost ACK) or expired: confirm without redelivering.
                    if event.offline {
                        let ack = Event {
                            from: event.from.clone(),
                            ..Event::request("ack", event.id.clone())
                        };
                        self.write_event(&ack).await?;
                    }
                    return Ok(());
                }
                event.data = data;
                event.body.clear();
            }
            "peer.up" | "peer.down" | "group.changed" => {}
            _ => {
                let pending = self.link.shared.lock().pending.remove(&event.id);
                if let Some(p) = pending {
                    let result = if event.kind == "error" {
                        Err(Error::Relay(event.code.clone()))
                    } else if !p.expected.contains(&event.kind.as_str()) {
                        Err(Error::Protocol("unexpected reply type"))
                    } else {
                        Ok(event)
                    };
                    let _ = p.reply.send(result);
                }
                return Ok(());
            }
        }
        self.events
            .try_send(event)
            .map_err(|_| Error::Protocol("event receive overflow"))
    }
}

/// Waits for close without holding the watch borrow, which would make the future `!Send`.
pub(crate) async fn closed_signal(closed: &mut watch::Receiver<bool>) {
    let _ = closed.wait_for(|closed| *closed).await;
}
