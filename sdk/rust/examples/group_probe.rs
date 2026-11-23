//! Group interop probe (scripts/group-interop.py): runs one `group_action` against the
//! config file at argv[1] with the durable state machine and writes the config back.
use common_relay::{GroupHttp, Groups};
use serde_json::{json, Value};
use std::{env, fs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("missing config path")?;
    let config: Value = serde_json::from_slice(&fs::read(&path)?)?;
    let mut keep = |_: &Value| Ok(());
    let mut g = Groups {
        config,
        api: GroupHttp { local: true },
        save: &mut keep,
        local: true,
    };
    let action = g.config["group_action"].as_str().unwrap_or("").to_owned();
    let device = g.config["device"].as_str().unwrap_or("").to_owned();
    let result = match action.as_str() {
        "rename" => {
            g.rename(&device, "Updated device")?;
            json!({})
        }
        "leave" => {
            g.exit(false)?;
            json!({})
        }
        "disband" => {
            g.exit(true)?;
            json!({})
        }
        "create" => {
            g.config.as_object_mut().ok_or("config")?.remove("group");
            g.create("My devices", "Creator")?;
            json!({})
        }
        "join" => {
            let inv = if let Some(link) = g.config["invitation_link"].as_str() {
                g.resolve(link, None)?
            } else {
                g.config["invitation"].clone()
            };
            g.join(inv, &device)?;
            json!({})
        }
        "finish" => json!(g.finish_join()?),
        "invite" => {
            let mode = g.config["invite_mode"]
                .as_str()
                .unwrap_or("manual")
                .to_owned();
            let link = g.invite(&mode)?;
            let mut inv = g.config["issued_invitation"].clone();
            inv["short_link"] = json!(link);
            inv
        }
        "approve" => {
            // The script supplies the request it fetched; the manager compares codes first.
            g.config["join_request"] = g.config["request"].clone();
            let code = g.code()?;
            g.approve(&code, false)?;
            json!({})
        }
        "remove" => {
            let device = g.config["remove"]
                .as_str()
                .ok_or("missing device")?
                .to_owned();
            g.remove(&device)?;
            json!({})
        }
        _ => g.refresh()?,
    };
    g.config["result"] = result;
    fs::write(path, serde_json::to_vec(&g.config)?)?;
    Ok(())
}
