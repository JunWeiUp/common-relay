use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use crate::secretstream::{aad, DecryptStream, EncryptStream};
use crate::{generate_key_pair, Error, Identity, Options};

const LOCAL: Options = Options {
    allow_local_test: true,
    password: None,
};
const RELAY_PASSWORD: &str = "local-test-access-1";

fn vectors() -> HashMap<String, String> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/v2/crypto-vectors.json"
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
        "/../../protocol/v2/crypto-vectors.json"
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

#[tokio::test]
async fn files_https_provider_and_no_redirects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { while listener.accept().await.is_ok() {} });
    let files = crate::RelayFiles::new(
        &format!("https://{address}/v2/files"),
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
            let reply = format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: http://{target_address}/v2/files\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(reply.as_bytes()).await;
        }
    });
    let files = crate::RelayFiles::new(
        &format!("http://{source_address}/v2/files"),
        &token(),
        LOCAL,
    )
    .unwrap();
    assert_eq!(files.inbox().await, Err(Error::Http(307)));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!reached.load(Ordering::SeqCst), "redirect followed");
    for bad in [
        "http://127.0.0.1:1/v2/files",
        "https://relay.example.com/v2/other",
        "https://u@relay.example.com/v2/files",
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

#[tokio::test]
async fn access_password_validated_and_redacted() {
    for bad in [
        "short",
        "has space1",
        "tab\tpassword",
        &"a".repeat(129),
        "pässword1",
    ] {
        let options = Options {
            allow_local_test: true,
            password: Some(bad.to_owned()),
        };
        assert!(matches!(
            crate::RelayFiles::for_relay_endpoint("ws://127.0.0.1:9/v2/ws", &token(), options),
            Err(Error::Invalid(_))
        ));
        let config = serde_json::json!({"url": "ws://127.0.0.1:9/v2/ws", "password": bad});
        assert!(crate::GroupHttp { local: true }.check(&config).is_err());
    }
    assert!(crate::GroupHttp { local: true }
        .check(&serde_json::json!({"url": "ws://127.0.0.1:9/v2/ws", "password": 5}))
        .is_err());
    let options = Options {
        allow_local_test: true,
        password: Some(RELAY_PASSWORD.to_owned()),
    };
    assert!(!format!("{options:?}").contains(RELAY_PASSWORD));
    assert!(
        crate::RelayFiles::for_relay_endpoint("ws://127.0.0.1:9/v2/ws", &token(), options).is_ok()
    );
}

/// Captures one raw HTTP request and answers `{}`.
async fn capture_http() -> (String, tokio::task::JoinHandle<String>) {
    use tokio::io::AsyncReadExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut data = Vec::new();
        let mut buf = [0u8; 4096];
        while !data.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}")
            .await
            .unwrap();
        String::from_utf8_lossy(&data).to_lowercase()
    });
    (format!("ws://127.0.0.1:{port}/v2/ws"), task)
}

#[tokio::test]
async fn groups_send_access_header_only_when_configured() {
    let call = |c: serde_json::Value| {
        tokio::task::spawn_blocking(move || {
            crate::GroupApi::call(
                &crate::GroupHttp { local: true },
                &c,
                "GET",
                "/group",
                None,
                None,
            )
        })
    };
    let (url, task) = capture_http().await;
    call(serde_json::json!({"url": url, "password": RELAY_PASSWORD}))
        .await
        .unwrap()
        .unwrap();
    let request = task.await.unwrap();
    assert!(request.contains(&format!("relay-access: {}", RELAY_PASSWORD.to_lowercase())));

    let (url, task) = capture_http().await;
    call(serde_json::json!({"url": url}))
        .await
        .unwrap()
        .unwrap();
    assert!(!task.await.unwrap().contains("relay-access"));
}

#[tokio::test]
async fn files_send_access_header() {
    let (url, task) = capture_http().await;
    let options = Options {
        allow_local_test: true,
        password: Some(RELAY_PASSWORD.to_owned()),
    };
    let files = crate::RelayFiles::for_relay_endpoint(&url, &token(), options).unwrap();
    let _ = files.inbox().await;
    let request = task.await.unwrap();
    assert!(request.contains(&format!("relay-access: {}", RELAY_PASSWORD.to_lowercase())));
}

#[test]
fn retired_v1_endpoints_rejected() {
    for url in [
        "wss://relay.example.com/relay/v1/ws",
        "wss://relay.example.com/v2/ws/",
        "wss://relay.example.com/",
    ] {
        assert!(
            crate::GroupHttp { local: false }
                .check(&serde_json::json!({ "url": url }))
                .is_err(),
            "{url}"
        );
        assert!(crate::RelayFiles::for_relay_endpoint(url, &token(), Options::default()).is_err());
    }
    assert!(crate::RelayFiles::new(
        "https://relay.example.com/relay/v1/files",
        &token(),
        Options::default()
    )
    .is_err());
    assert!(crate::GroupHttp { local: false }
        .check(&serde_json::json!({"url": "wss://relay.example.com/v2/ws"}))
        .is_ok());
}
