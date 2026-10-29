//! Echo is an isolated local interop probe; never point it at production identities.
//!
//! Without `state_path` it echoes online messages (lightweight interop, Python connects first).
//! With `state_path` it opens a private journal, echoes offline messages as new offline
//! messages and acknowledges them, and echoes every accepted stream until the peer's FINAL.
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use common_relay::{new_message_id, Client, Identity, Options, RelayJournal, RelayStream};
use serde::Deserialize;

#[derive(Deserialize)]
struct Config {
    app: String,
    group: String,
    device: String,
    secret_key: String,
    trusted_peers: HashMap<String, String>,
    url: String,
    token: String,
    allow_local_test: bool,
    #[serde(default)]
    state_path: Option<String>,
}

async fn echo_stream(stream: RelayStream) -> common_relay::Result<()> {
    while !stream.received_final() {
        let data = stream.receive().await?;
        stream.send(&data, stream.received_final()).await?;
    }
    Ok(())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        return Err("usage: echo test-config.json".into());
    }
    let config: Config = serde_json::from_str(&std::fs::read_to_string(&args[1])?)?;
    if !config.allow_local_test {
        return Err("local tests only".into());
    }
    let identity = Arc::new(Identity::new(
        &config.app,
        &config.group,
        &config.device,
        &config.secret_key,
        config.trusted_peers,
    )?);
    let options = Options {
        allow_local_test: true,
    };
    let client = Arc::new(match &config.state_path {
        Some(path) => {
            let journal = Arc::new(RelayJournal::open(path)?);
            Client::connect_with_journal(&config.url, &config.token, identity, options, journal)
                .await?
        }
        None => {
            let client = Client::connect(&config.url, &config.token, identity, options).await?;
            if !client.peers().await?.iter().any(|p| p.device == "python") {
                return Err("Python peer missing".into());
            }
            client
        }
    });
    println!("READY");
    loop {
        let event = client.next_event().await?;
        match event.kind.as_str() {
            "message" if event.offline => {
                client
                    .message_offline(&event.from, &new_message_id()?, &event.data)
                    .await?;
                client.acknowledge(&event).await?;
            }
            "message" => {
                client.message(&event.from, &event.data).await?;
            }
            "stream.open" => {
                let client = client.clone();
                tokio::spawn(async move {
                    let result = match client.accept_stream(&event).await {
                        Ok(stream) => echo_stream(stream).await,
                        Err(err) => Err(err),
                    };
                    if let Err(err) = result {
                        eprintln!("stream echo failed: {err}");
                    }
                });
            }
            _ => {}
        }
    }
}

#[tokio::main]
async fn main() {
    let result = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(120), run()) => result.unwrap_or(Ok(())),
        _ = tokio::signal::ctrl_c() => Ok(()),
    };
    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
