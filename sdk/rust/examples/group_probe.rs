use common_relay::Groups;
use serde_json::{json, Value};
use std::{env, fs};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("missing config path")?;
    let config: Value = serde_json::from_slice(&fs::read(&path)?)?;
    let mut g = Groups::new(config, true)?;
    let action = g.config["group_action"].as_str().unwrap_or("").to_owned();
    let device = g.config["device"].as_str().unwrap_or("").to_owned();
    let result = match action.as_str() {
        "rename" => {
            g.rename(&device, "Updated device").await?;
            json!({})
        }
        "leave" => {
            g.prepare_exit(false).await?;
            g.exit().await?;
            json!({})
        }
        "disband" => {
            g.prepare_exit(true).await?;
            g.exit().await?;
            json!({})
        }
        "create" => {
            g.config.as_object_mut().ok_or("config")?.remove("group");
            g.prepare_create("My devices", "Creator")?;
            g.create().await?;
            json!({})
        }
        "join" => {
            let inv = if let Some(link) = g.config["invitation_link"].as_str() {
                g.resolve_invitation(link).await?
            } else {
                g.config["invitation"].clone()
            };
            g.join(&inv, &device).await?;
            json!({})
        }
        "finish" => json!(g.finish_join().await?),
        "invite" => {
            let mode = g.config["invite_mode"]
                .as_str()
                .unwrap_or("manual")
                .to_owned();
            let compact = g.config["compact"] == true;
            g.invite(&mode, compact).await?
        }
        "approve" => {
            let inv = g.config["invitation"].clone();
            let request = g.config["request"].clone();
            g.approve(&inv, &request, false).await?;
            json!({})
        }
        "remove" => {
            let device = g.config["remove"]
                .as_str()
                .ok_or("missing device")?
                .to_owned();
            g.remove(&device).await?;
            json!({})
        }
        _ => g.refresh().await?,
    };
    g.config["result"] = result;
    fs::write(path, serde_json::to_vec(&g.config)?)?;
    Ok(())
}
