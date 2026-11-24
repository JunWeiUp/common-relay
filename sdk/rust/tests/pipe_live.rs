//! `/v2/ws` message client against a real loopback relay (`COMMON_RELAY_BINARY`, default
//! `build/common-relay`; build it with `go build -o build/common-relay ./cmd/common-relay`).
//! Skipped when the binary is missing. Test identities only, in a temporary directory.
use common_relay::{
    generate_key_pair, policy, Error, GroupHttp, Groups, Identity, Journal, Options, Pipe,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};

const ACCESS: &str = "test-access-password";

struct Relay {
    child: Child,
    url: String,
    dir: PathBuf,
}
impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn binary() -> Option<PathBuf> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let path = std::env::var("COMMON_RELAY_BINARY")
        .map(PathBuf::from)
        .unwrap_or(root.join("build/common-relay"));
    path.exists().then_some(path)
}

fn sha(s: &str) -> String {
    hex::encode(Sha256::digest(s.as_bytes()))
}

async fn start() -> Option<Relay> {
    let bin = binary()?;
    let dir = std::env::temp_dir().join(format!(
        "cr-pipe-{}",
        common_relay::new_message_id().unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("access"), sha(ACCESS)).unwrap();
    std::fs::write(dir.join("admin"), sha("test-v2-admin-secret")).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let child = Command::new(bin)
        .args(["serve", "--data"])
        .arg(dir.join("server"))
        .args([
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--disk-reserve",
            "0",
            "--self-service-apps",
            "example",
            "--access-password-file",
        ])
        .arg(dir.join("access"))
        .arg("--v2-admin-hash-file")
        .arg(dir.join("admin"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..250 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Some(Relay {
                child,
                url: format!("ws://127.0.0.1:{port}/v2/ws"),
                dir,
            });
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();
    panic!("relay did not start");
}

fn options() -> Options {
    Options {
        allow_local_test: true,
        password: Some(ACCESS.into()),
    }
}

fn groups(config: Value) -> Groups<'static, GroupHttp> {
    Groups {
        config,
        api: GroupHttp { local: true },
        save: Box::leak(Box::new(|_: &Value| Ok(()))),
        local: true,
    }
}

/// Two devices enrolled through the signed group flow; returns their configs.
fn enroll(url: &str) -> (Value, Value) {
    let device = |name: &str| {
        let (secret, _public) = generate_key_pair().unwrap();
        json!({"url":url,"password":ACCESS,"app":"example","device":name,"secret_key":secret})
    };
    let mut owner = groups(device("mac"));
    owner.create("Test", "mac").unwrap();
    let mut peer = groups(device("phone"));
    let link = owner.invite("auto").unwrap();
    let resolved = peer.resolve(&link, None).unwrap();
    assert!(peer.join(resolved, "phone").unwrap());
    owner.refresh().unwrap();
    peer.refresh().unwrap();
    (owner.config.clone(), peer.config.clone())
}

fn identity(config: &Value, trust: bool) -> Identity {
    let peers: Vec<(String, String)> = if trust {
        config["trusted_peers"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
            .collect()
    } else {
        vec![]
    };
    Identity::new(
        "example",
        config["group"].as_str().unwrap(),
        config["device"].as_str().unwrap(),
        config["secret_key"].as_str().unwrap(),
        peers,
    )
    .unwrap()
}

async fn connect(relay: &Relay, config: &Value, trust: bool, journal: &Path) -> Pipe {
    Pipe::connect(
        &relay.url,
        config["token"].as_str().unwrap(),
        &options(),
        identity(config, trust),
        Some(Journal::open(journal).unwrap()),
    )
    .await
    .unwrap()
}

async fn next_of(pipe: &Pipe, kind: &str) -> Value {
    for _ in 0..100 {
        if let Some(event) = pipe.next_event(Duration::from_millis(100)).await.unwrap() {
            if event["type"] == kind {
                return event;
            }
        }
    }
    panic!("no {kind} event");
}

#[tokio::test(flavor = "multi_thread")]
async fn messages_offline_delivery_undecryptable_and_rejected_credentials() {
    let Some(relay) = start().await else {
        eprintln!("COMMON_RELAY_BINARY not built; skipping");
        return;
    };
    let url = relay.url.clone();
    let (mac, phone) = tokio::task::spawn_blocking(move || enroll(&url))
        .await
        .unwrap();
    // Offline exit checks against the verified roster: the last manager cannot abandon a
    // member (disband instead) and only a manager can disband.
    let (owner, member) = (groups(mac.clone()), groups(phone.clone()));
    assert_eq!(
        owner.check_exit(false).unwrap_err(),
        Error::Relay("LastManager".into())
    );
    assert!(owner.check_exit(true).is_ok());
    assert!(member.check_exit(false).is_ok());
    assert_eq!(
        member.check_exit(true).unwrap_err(),
        Error::Relay("ManagerRequired".into())
    );
    let journals = relay.dir.join("journals");
    let a = connect(&relay, &mac, true, &journals.join("a")).await;
    let b = connect(&relay, &phone, true, &journals.join("b")).await;
    let peers = a.peers().await.unwrap();
    assert!(
        peers["devices"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["device"] == "phone"),
        "{peers}"
    );

    // Offline message: delivered, decrypted, acknowledged; a retry with the same id is served
    // from the journal instead of being sealed again.
    let id = "0123456789abcdef0123456789abcdef";
    let reply = a.message("phone", b"hello", true, Some(id)).await.unwrap();
    assert!(
        matches!(
            reply["type"].as_str(),
            Some("stored" | "forwarded" | "received")
        ),
        "{reply}"
    );
    let event = next_of(&b, "message").await;
    assert_eq!(
        (event["from"].as_str(), event["data"].as_str()),
        (Some("mac"), Some("aGVsbG8="))
    );
    b.acknowledge(
        "mac",
        event["id"].as_str().unwrap(),
        event["offline"] == true,
    )
    .unwrap();
    // Wait until the relay has deleted the offline message and notified `a`
    // before re-sending the same id or closing `b`.
    let rec = next_of(&a, "received").await;
    assert_eq!(rec["id"].as_str(), Some(id));
    assert!(a.message("phone", b"hello", true, Some(id)).await.is_ok());
    assert!(
        a.message("phone", b"different", true, Some(id))
            .await
            .is_err(),
        "same id, other content"
    );
    b.close();

    // An envelope the receiving connection cannot open (its trust map predates the sender)
    // is surfaced, never fatal, and redelivered once the sender is trusted.
    a.message(
        "phone",
        b"later",
        true,
        Some("fedcba9876543210fedcba9876543210"),
    )
    .await
    .unwrap();
    let untrusting = connect(&relay, &phone, false, &journals.join("b")).await;
    let event = next_of(&untrusting, "undecryptable").await;
    assert_eq!(
        (event["from"].as_str(), event["trusted"].as_bool()),
        (Some("mac"), Some(false))
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!untrusting.is_closed());
    untrusting.close();
    let trusting = connect(&relay, &phone, true, &journals.join("b2")).await;
    let event = next_of(&trusting, "message").await;
    assert_eq!(event["data"], "bGF0ZXI=");
    // Acknowledging it removes it for good.
    let later_id = event["id"].as_str().unwrap().to_string();
    trusting.acknowledge("mac", &later_id, true).unwrap();
    let rec = next_of(&a, "received").await;
    assert_eq!(rec["id"].as_str(), Some(later_id.as_str()));
    trusting.close();
    let again = connect(&relay, &phone, true, &journals.join("b3")).await;
    for _ in 0..10 {
        if let Some(event) = again.next_event(Duration::from_millis(100)).await.unwrap() {
            assert_ne!(
                event["type"], "message",
                "acknowledged messages are not redelivered"
            );
        }
    }
    again.close();

    // Rejected credentials are classified so callers stop reconnecting.
    let wrong = Options {
        allow_local_test: true,
        password: Some("wrong-access-password".into()),
    };
    let error = Pipe::connect(
        &relay.url,
        mac["token"].as_str().unwrap(),
        &wrong,
        identity(&mac, true),
        None,
    )
    .await
    .err()
    .unwrap();
    assert!(policy::authentication_failure(&error), "{error:?}");
    assert_eq!(
        policy::retry(policy::authentication_failure(&error), 4, 0),
        policy::Retry::Stop
    );
    assert!(matches!(error, Error::Http(401 | 403)));
}
