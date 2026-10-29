use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::{generate_key_pair, Client, Error, Event, Identity, Options, Peer};

const LOCAL: Options = Options {
    allow_local_test: true,
};

fn vectors() -> HashMap<String, String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/crypto-vectors.json"
    );
    let all: HashMap<String, serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    all.into_iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_owned())))
        .collect()
}
fn bob() -> Identity {
    let v = vectors();
    Identity::new(
        &v["app"],
        &v["group"],
        "bob",
        &v["bob_secret"],
        [("alice", &v["alice_public"])],
    )
    .unwrap()
}
fn alice() -> Identity {
    let v = vectors();
    Identity::new(
        &v["app"],
        &v["group"],
        "alice",
        &v["alice_secret"],
        [("bob", &v["bob_public"])],
    )
    .unwrap()
}
fn token() -> String {
    "x".repeat(64)
}

#[test]
fn crypto_vectors() {
    let v = vectors();
    let b = bob();
    assert_eq!(b.public_key(), v["bob_public"]);
    assert_eq!(
        b.open_message("alice", &v["id"], &v["message"]).unwrap(),
        b"hello"
    );
    let invalid = [
        ("alice", "02".repeat(16), v["message"].clone()),
        ("unknown", v["id"].clone(), v["message"].clone()),
        ("alice", v["id"].clone(), v["offline_message"].clone()),
        ("alice", v["id"].clone(), v["message"].clone() + "\n"),
    ];
    for (from, id, body) in invalid {
        assert!(
            b.open_message(from, &id, &body).is_err(),
            "accepted invalid envelope"
        );
    }
    let a = alice();
    let body = a.seal_message("bob", &v["id"], "你好".as_bytes()).unwrap();
    assert_eq!(
        b.open_message("alice", &v["id"], &body).unwrap(),
        "你好".as_bytes()
    );
    assert!(
        a.seal_message("bob", &v["id"], &[0; 200000]).is_err(),
        "accepted oversize message"
    );
    let mut tampered = base64::engine::general_purpose::STANDARD
        .decode(&body)
        .unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    let tampered = base64::engine::general_purpose::STANDARD.encode(tampered);
    assert!(
        b.open_message("alice", &v["id"], &tampered).is_err(),
        "accepted tampered envelope"
    );
    let low_order = "00".repeat(32);
    assert!(Identity::new(
        &v["app"],
        &v["group"],
        "alice",
        &v["alice_secret"],
        [("bob", &low_order)]
    )
    .is_err());
    let (secret, public) = generate_key_pair().unwrap();
    let i = Identity::new(
        "example",
        "test",
        "new",
        &secret,
        Vec::<(String, String)>::new(),
    )
    .unwrap();
    assert_eq!(i.public_key(), public);
    assert!(
        !format!("{i:?}").contains(&secret),
        "debug output leaks the secret"
    );
}

/// Serves each connection after checking the credential and sending a welcome.
// The handshake callback signature, including its error type, is fixed by tungstenite.
#[allow(clippy::result_large_err)]
async fn test_server<F, Fut>(mismatch: bool, handler: F) -> String
where
    F: Fn(WebSocketStream<TcpStream>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let handler = handler.clone();
            tokio::spawn(async move {
                let check = |request: &Request,
                             mut response: Response|
                 -> Result<Response, ErrorResponse> {
                    let auth = request
                        .headers()
                        .get("Authorization")
                        .and_then(|v| v.to_str().ok());
                    assert_eq!(
                        auth,
                        Some(format!("Bearer {}", token()).as_str()),
                        "missing credential"
                    );
                    response.headers_mut().insert(
                        "Sec-WebSocket-Protocol",
                        HeaderValue::from_static("common-relay.v1"),
                    );
                    Ok(response)
                };
                let Ok(mut ws) = tokio_tungstenite::accept_hdr_async(stream, check).await else {
                    return;
                };
                let b = bob();
                let device = if mismatch { "other" } else { "bob" };
                let identity = Peer {
                    app: b.app.clone(),
                    group: b.group.clone(),
                    device: device.into(),
                    public_key: b.public_key().into(),
                };
                let welcome = Event {
                    kind: "welcome".into(),
                    version: 1,
                    identity: Some(identity),
                    ..Event::default()
                };
                if ws
                    .send(Message::text(serde_json::to_string(&welcome).unwrap()))
                    .await
                    .is_err()
                {
                    return;
                }
                let _ = timeout(Duration::from_secs(5), handler(ws)).await;
            });
        }
    });
    format!("ws://{address}/relay/v1/ws")
}

async fn read_event(ws: &mut WebSocketStream<TcpStream>) -> Option<Event> {
    loop {
        match ws.next().await? {
            Ok(Message::Text(text)) => return Some(serde_json::from_str(text.as_str()).unwrap()),
            Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            _ => return None,
        }
    }
}
async fn write_event(ws: &mut WebSocketStream<TcpStream>, event: &Event) -> bool {
    ws.send(Message::text(serde_json::to_string(event).unwrap()))
        .await
        .is_ok()
}
async fn idle(mut ws: WebSocketStream<TcpStream>) {
    while read_event(&mut ws).await.is_some() {}
}

#[tokio::test]
async fn client_messages_peers_and_cancellation() {
    let endpoint = test_server(false, |mut ws| async move {
        let v = vectors();
        while let Some(e) = read_event(&mut ws).await {
            let response = if e.kind == "peers" {
                let alice = Peer {
                    app: v["app"].clone(),
                    group: v["group"].clone(),
                    device: "alice".into(),
                    public_key: v["alice_public"].clone(),
                };
                Event {
                    kind: "peers".into(),
                    id: e.id.clone(),
                    devices: vec![alice],
                    ..Event::default()
                }
            } else {
                let data = alice().open_message("bob", &e.id, &e.body).unwrap();
                assert!(data == b"hello" && !e.offline, "invalid message");
                Event {
                    kind: "forwarded".into(),
                    id: e.id.clone(),
                    ..Event::default()
                }
            };
            if !write_event(&mut ws, &response).await {
                return;
            }
            if e.kind == "message" {
                let incoming = Event {
                    kind: "message".into(),
                    id: v["id"].clone(),
                    from: "alice".into(),
                    body: v["message"].clone(),
                    ..Event::default()
                };
                if !write_event(&mut ws, &incoming).await {
                    return;
                }
            }
        }
    })
    .await;
    let c = Client::connect(&endpoint, &token(), Arc::new(bob()), LOCAL)
        .await
        .unwrap();
    let peers = c.peers().await.unwrap();
    assert!(peers.len() == 1 && peers[0].device == "alice");
    let receipt = c.message("alice", b"hello").await.unwrap();
    assert_eq!(receipt.kind, "forwarded");
    let event = c.next_event().await.unwrap();
    assert!(event.data == b"hello" && event.body.is_empty());
    assert!(
        timeout(Duration::from_millis(20), c.next_event())
            .await
            .is_err(),
        "cancel ignored"
    );
    c.close();
    assert!(c.peers().await.is_err(), "request after close");
    assert!(c.next_event().await.is_err());
}

#[tokio::test]
async fn fail_closed_and_request_cancellation() {
    let token = token();
    let insecure = Client::connect(
        "ws://127.0.0.1:1/relay/v1/ws",
        &token,
        Arc::new(bob()),
        Options::default(),
    )
    .await;
    assert!(
        matches!(insecure, Err(Error::Invalid(_))),
        "accepted insecure endpoint"
    );
    for bad in [
        "wss://relay.example.com/relay/v1/ws?",
        "wss://u@relay.example.com/relay/v1/ws",
        "wss://relay.example.com/other",
    ] {
        assert!(Client::connect(bad, &token, Arc::new(bob()), LOCAL)
            .await
            .is_err());
    }
    let endpoint = test_server(true, idle).await;
    assert!(
        Client::connect(&endpoint, &token, Arc::new(bob()), LOCAL)
            .await
            .is_err(),
        "accepted mismatched identity"
    );
    let endpoint = test_server(false, idle).await;
    assert!(Client::connect(&endpoint, "short", Arc::new(bob()), LOCAL)
        .await
        .is_err());
    let c = Arc::new(
        Client::connect(&endpoint, &token, Arc::new(bob()), LOCAL)
            .await
            .unwrap(),
    );
    assert!(
        timeout(Duration::from_millis(20), c.peers()).await.is_err(),
        "timeout ignored"
    );
    assert!(c.pending_count() == 0, "pending request leaked");
    let pending = tokio::spawn({
        let c = c.clone();
        async move { c.peers().await }
    });
    while c.pending_count() == 0 {
        tokio::task::yield_now().await;
    }
    c.close();
    assert!(
        pending.await.unwrap().is_err(),
        "close did not reject pending request"
    );
}

#[tokio::test]
async fn relay_errors_reject_requests() {
    let endpoint = test_server(false, |mut ws| async move {
        while let Some(e) = read_event(&mut ws).await {
            let reply = Event {
                kind: "error".into(),
                id: e.id,
                code: "rate_limited".into(),
                ..Event::default()
            };
            if !write_event(&mut ws, &reply).await {
                return;
            }
        }
    })
    .await;
    let c = Client::connect(&endpoint, &token(), Arc::new(bob()), LOCAL)
        .await
        .unwrap();
    assert_eq!(c.peers().await, Err(Error::Relay("rate_limited".into())));
    assert!(
        c.err().is_none(),
        "relay errors must not close the connection"
    );
}

#[tokio::test]
async fn redirect_never_forwards_credential() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let reached = Arc::new(AtomicBool::new(false));
    tokio::spawn({
        let reached = reached.clone();
        async move {
            while target.accept().await.is_ok() {
                reached.store(true, Ordering::SeqCst);
            }
        }
    });
    let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let source_address = source.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = source.accept().await {
            let mut buffer = [0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await;
            let reply = format!("HTTP/1.1 302 Found\r\nLocation: ws://{target_address}/relay/v1/ws\r\nContent-Length: 0\r\n\r\n");
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    let endpoint = format!("ws://{source_address}/relay/v1/ws");
    assert!(Client::connect(&endpoint, &token(), Arc::new(bob()), LOCAL)
        .await
        .is_err());
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!reached.load(Ordering::SeqCst), "redirect followed");
}

#[tokio::test]
async fn offline_reception_rejected() {
    let endpoint = test_server(false, |mut ws| async move {
        let v = vectors();
        let message = Event {
            kind: "message".into(),
            id: v["id"].clone(),
            from: "alice".into(),
            body: v["message"].clone(),
            offline: true,
            ..Event::default()
        };
        write_event(&mut ws, &message).await;
        assert!(read_event(&mut ws).await.is_none(), "unexpected ACK");
    })
    .await;
    let c = Client::connect(&endpoint, &token(), Arc::new(bob()), LOCAL)
        .await
        .unwrap();
    let err = c.next_event().await.unwrap_err();
    assert!(
        err.to_string().contains("offline"),
        "offline not rejected: {err}"
    );
}

#[tokio::test]
async fn wss_uses_bundled_tls_provider() {
    // A server that drops the connection reaches TLS setup without needing a certificate.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { while listener.accept().await.is_ok() {} });
    let endpoint = format!("wss://{address}/relay/v1/ws");
    let result = Client::connect(&endpoint, &token(), Arc::new(bob()), Options::default()).await;
    assert!(
        matches!(result, Err(Error::Connection(_))),
        "{:?}",
        result.err()
    );
}

// ---- Offline journal, streams and files ----

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::secretstream::{aad, DecryptStream, EncryptStream};
use crate::{new_message_id, RelayJournal, RelayStream};

/// A private temporary directory removed on drop.
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "common-relay-rust-{}",
            hex::encode(crate::crypto::random::<8>().unwrap())
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn all_vectors() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/crypto-vectors.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn stream_and_offline_vectors() {
    let v = all_vectors();
    let id = v["id"].as_str().unwrap();
    let ad = aad("example", "test", "alice", "bob", "stream", id, 0);
    assert_eq!(String::from_utf8(ad.clone()).unwrap(), v["stream_aad"]);
    let mut stream = DecryptStream::new(&v["stream_descriptor"]).unwrap();
    let record = hex::decode(v["stream_ciphertext"].as_str().unwrap()).unwrap();
    assert_eq!(stream.pull(&record, &ad).unwrap(), b"hello");
    assert!(stream.finished, "vector record is FINAL");
    assert!(
        stream.pull(&record, &ad).is_err(),
        "accepted record after final"
    );
    let mut wrong_aad = DecryptStream::new(&v["stream_descriptor"]).unwrap();
    let other = aad("example", "test", "alice", "bob", "stream", id, 1);
    assert!(
        wrong_aad.pull(&record, &other).is_err(),
        "accepted wrong AAD"
    );

    let (data, expires) = bob()
        .open_message_parts("alice", id, v["offline_message"].as_str().unwrap())
        .unwrap();
    assert_eq!(expires, v["offline_expires"].as_i64());
    assert_eq!(data, b"hello");
}

#[test]
fn secretstream_rejects_reorder_duplicates_and_tampering() {
    let mut sender = EncryptStream::new().unwrap();
    let ad = |seq| aad("a", "g", "x", "y", "stream", "01", seq);
    let records: Vec<Vec<u8>> = (0..3)
        .map(|i| {
            sender
                .push(&[i as u8; 70000 - 65536 + 10], &ad(i), i == 2)
                .unwrap()
        })
        .collect();
    assert!(
        sender.push(b"late", &ad(3), false).is_err(),
        "push after final"
    );
    assert!(
        sender.push(&[0; 65520], &ad(3), false).is_err(),
        "oversize record"
    );
    let descriptor = sender.descriptor();
    let mut reorder = DecryptStream::new(&descriptor).unwrap();
    assert!(
        reorder.pull(&records[1], &ad(1)).is_err(),
        "accepted reorder"
    );
    let mut duplicate = DecryptStream::new(&descriptor).unwrap();
    duplicate.pull(&records[0], &ad(0)).unwrap();
    assert!(
        duplicate.pull(&records[0], &ad(1)).is_err(),
        "accepted duplicate"
    );
    let mut tampered = DecryptStream::new(&descriptor).unwrap();
    let mut bad = records[0].clone();
    bad[5] ^= 1;
    assert!(tampered.pull(&bad, &ad(0)).is_err(), "accepted tampering");
    let mut ok = DecryptStream::new(&descriptor).unwrap();
    for (i, record) in records.iter().enumerate() {
        assert_eq!(ok.pull(record, &ad(i as u64)).unwrap()[0], i as u8);
    }
    assert!(ok.finished);
    assert!(DecryptStream::new(&serde_json::json!({"key": "00"})).is_err());
}

#[test]
fn journal_restart_cleanup_and_single_owner() {
    let dir = TempDir::new();
    let now = Arc::new(Mutex::new(1_000_000i64));
    let clock = {
        let now = now.clone();
        move || *now.lock().unwrap()
    };
    let open = || RelayJournal::open_with_clock(dir.path(), clock.clone());
    let journal = open().unwrap();
    assert!(open().is_err(), "second owner accepted");
    let send = |j: &RelayJournal, id: &str, data: &[u8], body: &'static str| {
        j.prepare("scope", id, "bob", data, 60, |_| Ok(body.into()))
    };
    let first = match send(&journal, "id", b"abc", "cipher").unwrap() {
        crate::journal::Prepared::Send { body, expires } => (body, expires),
        _ => panic!("expected send"),
    };
    drop(journal);
    *now.lock().unwrap() += 30;
    let journal = open().unwrap();
    let retry = journal
        .prepare("scope", "id", "bob", b"abc", 86400, |_| {
            panic!("re-encrypted")
        })
        .unwrap();
    assert!(
        matches!(retry, crate::journal::Prepared::Send { body, expires } if (body.clone(), expires) == first)
    );
    assert!(
        send(&journal, "id", b"changed", "x").is_err(),
        "content conflict"
    );
    assert!(
        journal
            .prepare("scope", "id", "carol", b"abc", 60, |_| Ok("x".into()))
            .is_err(),
        "recipient conflict"
    );
    journal.acknowledge("scope", "alice", "in").unwrap();
    assert!(journal.contains("scope", "alice", "in").unwrap());
    assert!(
        !journal.contains("other", "alice", "in").unwrap(),
        "scope isolation"
    );
    *now.lock().unwrap() += 30;
    assert_eq!(journal.cleanup().unwrap(), 1);
    assert!(
        send(&journal, "id", b"abc", "x").is_err(),
        "expired message resent"
    );
    for entry in std::fs::read_dir(dir.path()).unwrap() {
        let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
        assert!(!text.contains("cipher") && !text.contains("abc"));
    }
    journal
        .prepare("scope", "done", "bob", b"abc", 60, |_| Ok("c".into()))
        .unwrap();
    journal.complete("scope", "done").unwrap();
    assert!(matches!(
        send(&journal, "done", b"abc", "x").unwrap(),
        crate::journal::Prepared::Received
    ));
    *now.lock().unwrap() += 7 * 86400;
    journal.cleanup().unwrap();
    assert!(!journal.contains("scope", "alice", "in").unwrap());
    let records = || {
        std::fs::read_dir(dir.path())
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .path()
                    .extension()
                    .is_some_and(|x| x == "json")
            })
            .count()
    };
    assert_eq!(records(), 0, "retention not purged");
    for i in 0..300 {
        send(&journal, &format!("{i:032x}"), b"abc", "c").unwrap();
    }
    *now.lock().unwrap() += 60;
    assert_eq!(journal.cleanup().unwrap(), 256, "cleanup not bounded");
    assert_eq!(journal.cleanup().unwrap(), 44);
    assert!(journal
        .prepare("scope", "x", "bob", b"abc", 86401, |_| Ok("c".into()))
        .is_err());
}

fn offline_from_alice(id: &str, data: &[u8], expires: i64) -> Event {
    Event {
        kind: "message".into(),
        id: id.into(),
        from: "alice".into(),
        body: alice()
            .seal_offline_message("bob", id, data, expires)
            .unwrap(),
        offline: true,
        ..Event::default()
    }
}

#[tokio::test]
async fn offline_requires_journal() {
    let endpoint = test_server(false, idle).await;
    let c = Client::connect(&endpoint, &token(), Arc::new(bob()), LOCAL)
        .await
        .unwrap();
    assert!(c
        .message_offline("alice", &new_message_id().unwrap(), b"x")
        .await
        .is_err());
    let event = offline_from_alice(&"03".repeat(16), b"x", crate::crypto::now() + 60);
    assert!(c.acknowledge(&event).await.is_err());
    assert_eq!(c.cleanup(), Ok(0));
}

#[tokio::test]
async fn offline_send_reuses_ciphertext_and_records_receipt() {
    let seen: Arc<Mutex<Vec<Event>>> = Arc::default();
    let endpoint = test_server(false, {
        let seen = seen.clone();
        move |mut ws| {
            let seen = seen.clone();
            async move {
                while let Some(e) = read_event(&mut ws).await {
                    let count = {
                        let mut seen = seen.lock().unwrap();
                        seen.push(e.clone());
                        seen.len()
                    };
                    let kind = if count < 3 { "stored" } else { "received" };
                    let reply = Event {
                        kind: kind.into(),
                        id: e.id,
                        ..Event::default()
                    };
                    if !write_event(&mut ws, &reply).await {
                        return;
                    }
                }
            }
        }
    })
    .await;
    let dir = TempDir::new();
    let journal = Arc::new(RelayJournal::open(dir.path()).unwrap());
    let c = Client::connect_with_journal(&endpoint, &token(), Arc::new(bob()), LOCAL, journal)
        .await
        .unwrap();
    let id = new_message_id().unwrap();
    assert_eq!(
        c.message_offline("alice", &id, b"hi").await.unwrap().kind,
        "stored"
    );
    assert_eq!(
        c.message_offline("alice", &id, b"hi").await.unwrap().kind,
        "stored"
    );
    assert_eq!(
        c.message_offline("alice", &id, b"hi").await.unwrap().kind,
        "received"
    );
    assert_eq!(
        c.message_offline("alice", &id, b"hi").await.unwrap().kind,
        "received"
    );
    assert!(c.message_offline("alice", &id, b"other").await.is_err());
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 3, "received state must not resend");
    for e in &seen {
        assert!(e.offline && e.body == seen[0].body && e.expires == seen[0].expires);
        assert!(e.ttl >= 1 && e.ttl <= 86400);
    }
    let (data, expires) = alice()
        .open_message_parts("bob", &id, &seen[0].body)
        .unwrap();
    assert_eq!(
        (data.as_slice(), expires),
        (&b"hi"[..], Some(seen[0].expires))
    );
    assert!(seen[0].expires > crate::crypto::now() + 86000);
}

#[tokio::test]
async fn offline_receive_acks_once_and_dedupes() {
    let acks: Arc<Mutex<Vec<String>>> = Arc::default();
    let endpoint = test_server(false, {
        let acks = acks.clone();
        move |mut ws| {
            let acks = acks.clone();
            async move {
                let now = crate::crypto::now();
                let first = offline_from_alice(&"04".repeat(16), b"durable", now + 60);
                let expired = offline_from_alice(&"05".repeat(16), b"old", now - 1);
                let trigger = Event {
                    kind: "message".into(),
                    id: "06".repeat(16),
                    from: "alice".into(),
                    body: alice()
                        .seal_message("bob", &"06".repeat(16), b"next")
                        .unwrap(),
                    ..Event::default()
                };
                // Redelivery after the ACK and an expired message must both be auto-ACKed.
                for send in [first.clone(), first, expired] {
                    write_event(&mut ws, &send).await;
                    let Some(ack) = read_event(&mut ws).await else {
                        return;
                    };
                    assert_eq!((ack.kind.as_str(), ack.from.as_str()), ("ack", "alice"));
                    acks.lock().unwrap().push(ack.id.clone());
                    let reply = Event {
                        kind: "acked".into(),
                        id: ack.id,
                        ..Event::default()
                    };
                    write_event(&mut ws, &reply).await;
                }
                write_event(&mut ws, &trigger).await;
                idle(ws).await;
            }
        }
    })
    .await;
    let dir = TempDir::new();
    let journal = Arc::new(RelayJournal::open(dir.path()).unwrap());
    let c = Client::connect_with_journal(&endpoint, &token(), Arc::new(bob()), LOCAL, journal)
        .await
        .unwrap();
    let event = c.next_event().await.unwrap();
    assert!(event.offline && event.data == b"durable");
    c.acknowledge(&event).await.unwrap();
    let next = c.next_event().await.unwrap();
    assert_eq!(
        next.data, b"next",
        "duplicate or expired message redelivered"
    );
    assert_eq!(
        *acks.lock().unwrap(),
        vec!["04".repeat(16), "04".repeat(16), "05".repeat(16)]
    );
}

#[tokio::test]
async fn files_https_provider_and_no_redirects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { while listener.accept().await.is_ok() {} });
    let files = crate::RelayFiles::new(
        &format!("https://{address}/relay/v1/files"),
        &token(),
        Options::default(),
    )
    .unwrap();
    let result = files.inbox().await;
    assert!(matches!(result, Err(Error::Connection(_))), "{result:?}");

    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_address = target.local_addr().unwrap();
    let reached = Arc::new(AtomicBool::new(false));
    tokio::spawn({
        let reached = reached.clone();
        async move {
            while target.accept().await.is_ok() {
                reached.store(true, Ordering::SeqCst);
            }
        }
    });
    let source = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let source_address = source.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = source.accept().await {
            let mut buffer = [0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await;
            let reply = format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target_address}/relay/v1/files\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    let files = crate::RelayFiles::new(
        &format!("http://{source_address}/relay/v1/files"),
        &token(),
        LOCAL,
    )
    .unwrap();
    assert_eq!(files.inbox().await, Err(Error::Http(307)));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!reached.load(Ordering::SeqCst), "redirect followed");
    for bad in [
        "http://127.0.0.1:1/relay/v1/files",
        "https://relay.example.com/relay/v1/other",
        "https://u@relay.example.com/relay/v1/files",
    ] {
        assert!(crate::RelayFiles::new(bad, &token(), Options::default()).is_err());
    }
    assert_eq!(
        crate::safe_file_name("../../etc/passwd").as_deref(),
        Some("passwd")
    );
    assert_eq!(crate::safe_file_name("..").as_deref(), None);
    assert_eq!(crate::safe_file_name("a\nb"), None);
    assert_eq!(
        crate::safe_file_name("C:\\x\\report.pdf").as_deref(),
        Some("report.pdf")
    );
}

#[test]
fn file_encryption_roundtrip_and_tamper() {
    let dir = TempDir::new();
    let source = dir.path().join("source.bin");
    let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source, &data).unwrap();
    let staged = dir.path().join("staged.enc");
    let a = alice();
    let b = bob();
    let descriptor = crate::prepare_file(
        &a,
        "bob",
        &source,
        &staged,
        serde_json::json!({"name": "source.bin"}),
    )
    .unwrap();
    assert!(crate::prepare_file(&a, "bob", &source, &staged, serde_json::json!({})).is_err());
    let info = crate::FileInfo {
        id: descriptor.id.clone(),
        to: "bob".into(),
        from: "alice".into(),
        size: descriptor.size,
        metadata: descriptor.metadata.clone(),
        sha256: descriptor.sha256.clone(),
        ..crate::FileInfo::default()
    };
    let out = dir.path().join("out.bin");
    let metadata = crate::decrypt_file(&b, "alice", &info, &staged, &out).unwrap();
    assert_eq!(metadata["name"], "source.bin");
    assert_eq!(std::fs::read(&out).unwrap(), data);
    assert!(
        crate::decrypt_file(&b, "alice", &info, &staged, &out).is_err(),
        "replaced an existing file"
    );
    // Truncating the FINAL record must never publish a destination, even with a matching digest.
    let mut cut = std::fs::read(&staged).unwrap();
    cut.truncate(cut.len() - 21);
    let cut_path = dir.path().join("cut.enc");
    std::fs::write(&cut_path, &cut).unwrap();
    let cut_info = crate::FileInfo {
        size: cut.len() as u64,
        sha256: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&cut)),
        ..info.clone()
    };
    let never = dir.path().join("never.bin");
    assert!(crate::decrypt_file(&b, "alice", &cut_info, &cut_path, &never).is_err());
    assert!(!never.exists());
    let mut flipped = std::fs::read(&staged).unwrap();
    flipped[10] ^= 1;
    std::fs::write(&cut_path, &flipped).unwrap();
    let flipped_info = crate::FileInfo {
        size: flipped.len() as u64,
        sha256: hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&flipped)),
        ..info.clone()
    };
    assert!(crate::decrypt_file(&b, "alice", &flipped_info, &cut_path, &never).is_err());
    assert!(!never.exists());
    let leftovers = std::fs::read_dir(dir.path())
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".partial")
        })
        .count();
    assert_eq!(leftovers, 0, "partial file left behind");
}

/// Known answers produced by libsodium (PyNaCl) for a fixed key and header, including rekey.
#[test]
fn secretstream_matches_libsodium() {
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let header = |text: &str| -> [u8; 24] { hex::decode(text).unwrap().try_into().unwrap() };
    let mut e = EncryptStream::with_key(
        key,
        header("9b3dda2ff4571e3150b2a6080c9510383abbab3358e05ae7"),
    );
    assert_eq!(
        hex::encode(e.push(b"hello", b"ad", false).unwrap()),
        "3ceff2b853c432c56535d20e784025247aae56420623"
    );
    assert_eq!(
        hex::encode(e.push(b"", b"", true).unwrap()),
        "8d586cb1c480c09a9976cbdd6b6f7359cf"
    );
    let mut e = EncryptStream::with_key(
        key,
        header("4fdb9cfa785f479a382dd1e8320d31abd84b3dcf68e179d6"),
    );
    e.push(b"hello", b"ad", false).unwrap();
    e.rekey_for_test();
    assert_eq!(
        hex::encode(e.push(&[b'x'; 40], b"", false).unwrap()),
        "9359cdc63e0fc0d1197792d1dc3a2c785ac555d557d948e3ac2285cd7c9d74d7438e49443eba092411b283cd8ab8daaf2106be4f02109b9bb8"
    );
}

/// A loopback relay from the prebuilt `build/common-relay`, with throwaway identities.
struct LocalRelay {
    process: std::process::Child,
    url: String,
    devices: HashMap<String, (String, String, String)>,
    _dir: TempDir,
}
impl Drop for LocalRelay {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
impl LocalRelay {
    async fn start(names: &[&str]) -> Option<Self> {
        let server = concat!(env!("CARGO_MANIFEST_DIR"), "/../../build/common-relay");
        if !Path::new(server).exists() {
            eprintln!("skipping: {server} not built");
            return None;
        }
        let dir = TempDir::new();
        let data = dir.path().join("server");
        let mut devices = HashMap::new();
        for name in names {
            let (secret, public) = generate_key_pair().unwrap();
            let credential = dir.path().join(format!("{name}.json"));
            let status = std::process::Command::new(server)
                .args(["device-add", "--data"])
                .arg(&data)
                .args(["--app", "example", "--group", "rust", "--device", name])
                .args(["--public-key", &public, "--credential-out"])
                .arg(&credential)
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(status.success());
            let value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&credential).unwrap()).unwrap();
            let token = value["token"].as_str().unwrap().to_owned();
            devices.insert(name.to_string(), (secret, public, token));
        }
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let process = std::process::Command::new(server)
            .arg("serve")
            .arg("--data")
            .arg(&data)
            .args([
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--disk-reserve",
                "0",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        for _ in 0..200 {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Some(Self {
            process,
            url: format!("ws://127.0.0.1:{port}/relay/v1/ws"),
            devices,
            _dir: dir,
        })
    }
    fn identity(&self, name: &str) -> Arc<Identity> {
        let peers: Vec<(String, String)> = self
            .devices
            .iter()
            .filter(|(n, _)| n.as_str() != name)
            .map(|(n, d)| (n.clone(), d.1.clone()))
            .collect();
        Arc::new(Identity::new("example", "rust", name, &self.devices[name].0, peers).unwrap())
    }
    fn token(&self, name: &str) -> &str {
        &self.devices[name].2
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_relay_offline_streams_and_files() {
    let Some(relay) = LocalRelay::start(&["alice", "bob"]).await else {
        return;
    };
    let alice_state = TempDir::new();
    let bob_state = TempDir::new();
    let alice_journal = Arc::new(RelayJournal::open(alice_state.path()).unwrap());
    let bob_journal = Arc::new(RelayJournal::open(bob_state.path()).unwrap());
    let alice = Client::connect_with_journal(
        &relay.url,
        relay.token("alice"),
        relay.identity("alice"),
        LOCAL,
        alice_journal,
    )
    .await
    .unwrap();

    // Offline while the recipient is disconnected; retry after the ACK reports `received`.
    let id = new_message_id().unwrap();
    assert_eq!(
        alice
            .message_offline("bob", &id, b"durable")
            .await
            .unwrap()
            .kind,
        "stored"
    );
    assert_eq!(
        alice
            .message_offline("bob", &id, b"durable")
            .await
            .unwrap()
            .kind,
        "stored"
    );
    let bob = Arc::new(
        Client::connect_with_journal(
            &relay.url,
            relay.token("bob"),
            relay.identity("bob"),
            LOCAL,
            bob_journal,
        )
        .await
        .unwrap(),
    );
    let event = timeout(Duration::from_secs(10), bob.next_event())
        .await
        .unwrap()
        .unwrap();
    assert!(event.offline && event.data == b"durable" && event.id == id);
    bob.acknowledge(&event).await.unwrap();
    assert_eq!(
        alice
            .message_offline("bob", &id, b"durable")
            .await
            .unwrap()
            .kind,
        "received"
    );

    // 1 MiB each way at once: more than the 8-record credit window, ending with FINAL.
    let payload: Vec<u8> = (0..(1u32 << 20)).map(|i| (i * 7 % 251) as u8).collect();
    let accepting = tokio::spawn({
        let bob = bob.clone();
        async move {
            loop {
                let event = bob.next_event().await.unwrap();
                if event.kind == "stream.open" {
                    return bob.accept_stream(&event).await.unwrap();
                }
            }
        }
    });
    let outgoing = Arc::new(alice.open_stream("bob").await.unwrap());
    let incoming = Arc::new(accepting.await.unwrap());
    let exchange = |stream: Arc<RelayStream>, data: Vec<u8>| async move {
        let sender = tokio::spawn({
            let stream = stream.clone();
            let data = data.clone();
            async move { stream.send(&data, true).await }
        });
        let mut received = Vec::new();
        while !stream.received_final() {
            received.extend(stream.receive().await.unwrap());
        }
        sender.await.unwrap().unwrap();
        received
    };
    let reversed: Vec<u8> = payload.iter().rev().copied().collect();
    let (a, b) = tokio::join!(
        exchange(outgoing.clone(), payload.clone()),
        exchange(incoming.clone(), reversed.clone())
    );
    assert!(a == reversed && b == payload, "stream data mismatch");
    assert!(
        outgoing.send(b"late", false).await.is_err(),
        "send after final"
    );
    outgoing.close().await.unwrap();

    // Files: upload, idempotent resume, ranged download resume, decrypt, delete.
    let files_dir = TempDir::new();
    let source = files_dir.path().join("photo.bin");
    let content: Vec<u8> = (0..2_500_000u32).map(|i| (i % 253) as u8).collect();
    std::fs::write(&source, &content).unwrap();
    let staged = files_dir.path().join("photo.enc");
    let descriptor = crate::prepare_file(
        &relay.identity("alice"),
        "bob",
        &source,
        &staged,
        serde_json::json!({"name": "../photo.bin"}),
    )
    .unwrap();
    let sender =
        crate::RelayFiles::for_relay_endpoint(&relay.url, relay.token("alice"), LOCAL).unwrap();
    let ready = sender.upload(&descriptor, &staged).await.unwrap();
    assert_eq!(
        (ready.state.as_str(), ready.offset),
        ("ready", descriptor.size)
    );
    assert_eq!(
        sender.upload(&descriptor, &staged).await.unwrap().state,
        "ready"
    );
    let conflicting = crate::FileDescriptor {
        sha256: "00".repeat(32),
        ..descriptor.clone()
    };
    assert!(
        sender.upload(&conflicting, &staged).await.is_err(),
        "ID conflict accepted"
    );
    let receiver =
        crate::RelayFiles::for_relay_endpoint(&relay.url, relay.token("bob"), LOCAL).unwrap();
    let inbox = receiver.inbox().await.unwrap();
    let info = inbox
        .iter()
        .find(|f| f.id == descriptor.id)
        .unwrap()
        .clone();
    assert_eq!(info.from, "alice");
    let download = files_dir.path().join("download.enc");
    std::fs::write(&download, &std::fs::read(&staged).unwrap()[..1500]).unwrap();
    receiver.download(&info, &download).await.unwrap();
    let name = crate::safe_file_name("../photo.bin").unwrap();
    let destination = files_dir.path().join(format!("received-{name}"));
    let metadata = crate::decrypt_file(
        &relay.identity("bob"),
        "alice",
        &info,
        &download,
        &destination,
    )
    .unwrap();
    assert_eq!(metadata["name"], "../photo.bin");
    assert_eq!(std::fs::read(&destination).unwrap(), content);
    receiver.delete(&info.id).await.unwrap();
    assert!(receiver
        .inbox()
        .await
        .unwrap()
        .iter()
        .all(|f| f.id != info.id));
    assert_eq!(receiver.status(&info.id).await, Err(Error::Http(404)));
}
