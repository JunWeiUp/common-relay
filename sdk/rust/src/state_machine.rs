//! Callback-driven draft-before-send group state machine and optional
//! direct-upgrade (`relay.direct.v1`) payload helpers.

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// Pipe `msg` topic reserved for optional LAN/direct candidate exchange (§4.9).
pub const DIRECT_UPGRADE_TOPIC: &str = "relay.direct.v1";

/// Pending credential/mutation draft persisted BEFORE issuing network requests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupDraft {
    pub draft_id: String,
    pub op: String, // "create" | "join" | "auto_join" | "rotate"
    pub app: String,
    pub group: String,
    pub device: String,
    pub secret_key: String,
    pub sign_secret_key: String,
    pub token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub invite_id: String,
    pub created_at: u64,
}

impl GroupDraft {
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|_| Error::Invalid("failed to encode group draft"))
    }

    pub fn from_json(raw: &str) -> Result<Self> {
        serde_json::from_str(raw).map_err(|_| Error::Invalid("invalid group draft json"))
    }
}

/// Application persistence callbacks for [`GroupStateMachine`].
pub trait DraftStore<T> {
    fn save_draft(&mut self, draft: &GroupDraft) -> Result<()>;
    fn load_draft(&self) -> Result<Option<GroupDraft>>;
    fn commit(&mut self, draft: &GroupDraft, result: &T) -> Result<()>;
    fn clear_draft(&mut self, draft_id: &str) -> Result<()>;
}

/// Coordinates draft-before-send mutations so mid-flight crashes never lose
/// freshly generated keys or device tokens.
pub struct GroupStateMachine<S> {
    store: S,
}

impl<S> GroupStateMachine<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    pub fn pending_draft<T>(&self) -> Result<Option<GroupDraft>>
    where
        S: DraftStore<T>,
    {
        self.store.load_draft()
    }

    /// Persists `draft` before invoking `action`. If `action` fails, the draft
    /// stays persisted for recovery; if it succeeds, `commit` and `clear_draft` run.
    pub fn execute<T, F>(&mut self, draft: &GroupDraft, action: F) -> Result<T>
    where
        S: DraftStore<T>,
        F: FnOnce(&GroupDraft) -> Result<T>,
    {
        self.store.save_draft(draft)?;
        let result = action(draft)?;
        self.store.commit(draft, &result)?;
        self.store.clear_draft(&draft.draft_id)?;
        Ok(result)
    }
}

/// Plaintext payload carried inside a §6 encrypted envelope on [`DIRECT_UPGRADE_TOPIC`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectUpgradeMessage {
    pub op: String, // "offer" | "answer" | "fallback"
    pub session: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub nonce: String,
}

impl DirectUpgradeMessage {
    pub fn validate(&self) -> Result<()> {
        match self.op.as_str() {
            "offer" | "answer" | "fallback" => {}
            _ => return Err(Error::Invalid("invalid direct upgrade op")),
        }
        if self.session.trim().is_empty() {
            return Err(Error::Invalid("direct upgrade session is required"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| Error::Invalid("failed to encode direct upgrade"))
    }

    pub fn decode(raw: &[u8]) -> Result<Self> {
        let msg: Self =
            serde_json::from_slice(raw).map_err(|_| Error::Invalid("invalid direct upgrade json"))?;
        msg.validate()?;
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct MemStore {
        draft: Option<String>,
        committed: Option<u64>,
        trace: Vec<&'static str>,
    }

    impl DraftStore<u64> for MemStore {
        fn save_draft(&mut self, draft: &GroupDraft) -> Result<()> {
            self.trace.push("save");
            self.draft = Some(draft.to_json()?);
            Ok(())
        }
        fn load_draft(&self) -> Result<Option<GroupDraft>> {
            match &self.draft {
                Some(raw) => Ok(Some(GroupDraft::from_json(raw)?)),
                None => Ok(None),
            }
        }
        fn commit(&mut self, _draft: &GroupDraft, result: &u64) -> Result<()> {
            self.trace.push("commit");
            self.committed = Some(*result);
            Ok(())
        }
        fn clear_draft(&mut self, _draft_id: &str) -> Result<()> {
            self.trace.push("clear");
            self.draft = None;
            Ok(())
        }
    }

    #[test]
    fn draft_persists_across_network_failure_and_commits_on_retry() {
        let mut sm = GroupStateMachine::new(MemStore::default());
        let draft = GroupDraft {
            draft_id: "d1".into(),
            op: "create".into(),
            app: "pv".into(),
            group: "g1".into(),
            device: "mac".into(),
            secret_key: "00".repeat(32),
            sign_secret_key: "11".repeat(32),
            token: "a".repeat(64),
            invite_id: String::new(),
            created_at: 1_700_000_000,
        };

        let err = sm
            .execute(&draft, |_| Err::<u64, _>(Error::Timeout))
            .unwrap_err();
        assert_eq!(err, Error::Timeout);
        assert_eq!(sm.pending_draft().unwrap(), Some(draft.clone()));
        assert_eq!(sm.store().committed, None);

        let rev = sm.execute(&draft, |_| Ok(1u64)).unwrap();
        assert_eq!(rev, 1);
        assert_eq!(sm.pending_draft().unwrap(), None);
        assert_eq!(sm.store().committed, Some(1));
        assert_eq!(sm.store().trace, vec!["save", "save", "commit", "clear"]);
    }

    #[test]
    fn direct_upgrade_roundtrip() {
        let msg = DirectUpgradeMessage {
            op: "offer".into(),
            session: "sess-1".into(),
            candidates: vec!["192.168.1.5:47899".into()],
            nonce: "abcd".into(),
        };
        let raw = msg.encode().unwrap();
        assert_eq!(DirectUpgradeMessage::decode(&raw).unwrap(), msg);
        assert!(DirectUpgradeMessage {
            op: "bad".into(),
            session: "s".into(),
            candidates: vec![],
            nonce: String::new(),
        }
        .encode()
        .is_err());
    }
}
