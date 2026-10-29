//! Common Relay v1 client: encrypted online/offline messages, streams, files,
//! presence and signed device groups.

mod client;
mod crypto;
mod files;
mod groups;
pub mod invitation_links;
mod journal;
mod payload;
mod secretstream;
mod stream;

pub use client::{Client, Event, Options, Peer};
pub use crypto::new_message_id;
pub use crypto::{generate_key_pair, Identity};
pub use files::{decrypt_file, prepare_file, safe_file_name, FileDescriptor, FileInfo, RelayFiles};
pub use groups::{advance_group, group_signing_key, unpack_group_entry, Groups};
pub use journal::{RelayJournal, CLEANUP_BATCH, DEFAULT_TTL, RETENTION};
pub use payload::{validate_payload, PayloadKind};
pub use stream::RelayStream;

/// Failures are cloneable so a closed connection reports the same cause to every caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0}")]
    Crypto(&'static str),
    #[error("{0}")]
    Protocol(&'static str),
    #[error("{0}")]
    Connection(&'static str),
    #[error("relay error: {0}")]
    Relay(String),
    #[error("relay request timed out")]
    Timeout,
    /// Unexpected HTTP status from a relay HTTP API.
    #[error("relay HTTP status {0}")]
    Http(u16),
    /// Local persistent state could not be read or written.
    #[error("{0}")]
    Storage(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
