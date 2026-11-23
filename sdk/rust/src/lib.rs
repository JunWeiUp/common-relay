//! Common Relay v2 SDK: signed device groups (`/v2/group`, `/v2/enroll`), end-to-end
//! encrypted resumable files (`/v2/files`), compact invitation links and v2 helpers
//! (Box/Pipe types, plugin bindings, `crs1` sealed bridge payloads), the `/v2/ws` message
//! client ([`Pipe`], with an offline delivery [`Journal`]) and client [`policy`] defaults.
//!
//! Every endpoint is derived from the device's `wss://host/v2/ws` relay URL.

mod access;
mod crypto;
mod files;
mod groups;
pub mod invitation_links;
mod journal;
mod payload;
mod pipe;
pub mod policy;
mod secretstream;
pub mod v2;

pub use access::{Options, ACCESS_HEADER};
pub use crypto::new_message_id;
pub use crypto::{generate_key_pair, Identity};
pub use files::{decrypt_file, prepare_file, safe_file_name, FileDescriptor, FileInfo, RelayFiles};
pub use groups::{
    advance_group, group_signing_key, now as unix_now, unpack_group_entry, GroupApi, GroupHttp,
    Groups,
};
pub use journal::Journal;
pub use payload::{validate_payload, PayloadKind};
pub use pipe::{Pipe, OFFLINE_TTL};

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
