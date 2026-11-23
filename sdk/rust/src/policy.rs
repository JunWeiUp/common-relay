//! Client policy defaults every Common Relay app should follow:
//! - rejected credentials (HTTP 401/403) stop reconnecting and need the user;
//! - other failures back off exponentially (1 s doubling to 30 s), and the backoff resets
//!   only after a connection stayed up for [`STABLE_CONNECTION_SECS`];
//! - a device that leaves a group should come back with a fresh device ID and transport
//!   key ([`fresh_identity`]): the old key is known to the members it left.
use crate::{generate_key_pair, new_message_id, Error, Result};

pub const STABLE_CONNECTION_SECS: u64 = 120;
pub const MAX_BACKOFF_SECS: u64 = 30;

/// True when the relay rejected this device's credentials or access password.
pub fn authentication_failure(error: &Error) -> bool {
    match error {
        Error::Http(status) => matches!(status, 401 | 403),
        Error::Relay(code) => authentication_code(code),
        _ => false,
    }
}

/// The same classification for an error code or message carried as text (e.g. across FFI).
pub fn authentication_code(code: &str) -> bool {
    ["401", "403"].iter().any(|status| {
        code == format!("RelayHttp{status}")
            || code.contains(&format!("({status})"))
            || code.contains(&format!("HTTP {status}"))
            || code.contains(&format!("status {status}"))
            || code.contains(&format!("'{status} "))
    }) || matches!(code, "unauthorized" | "forbidden")
}

/// What to do after a connection attempt ended.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Retry {
    /// Stop reconnecting and ask the user (rejected credentials).
    Stop,
    /// Wait this many seconds, then reconnect.
    After(u64),
}

/// `previous` is the delay used before this attempt (0 for the first), `connected` how long
/// the attempt stayed connected, `rejected` whether the credentials were refused.
pub fn retry(rejected: bool, previous: u64, connected: u64) -> Retry {
    if rejected {
        return Retry::Stop;
    }
    if previous == 0 || connected >= STABLE_CONNECTION_SECS {
        return Retry::After(1);
    }
    Retry::After((previous * 2).min(MAX_BACKOFF_SECS))
}

/// A fresh identity for a device that left its group.
#[derive(Debug)]
pub struct FreshIdentity {
    /// A new random device ID (UUID v4 text).
    pub device: String,
    /// New X25519 transport secret, hex.
    pub secret: String,
    /// Matching public key, hex.
    pub public_key: String,
}

pub fn fresh_identity() -> Result<FreshIdentity> {
    let raw = hex::decode(new_message_id()?).map_err(|_| Error::Invalid("random id"))?;
    let mut b = [0u8; 16];
    b.copy_from_slice(&raw);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    let device = format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    );
    let (secret, public_key) = generate_key_pair()?;
    Ok(FreshIdentity {
        device,
        secret,
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_rejections_stop_and_other_failures_back_off() {
        assert!(authentication_failure(&Error::Http(401)));
        assert!(authentication_failure(&Error::Http(403)));
        assert!(!authentication_failure(&Error::Http(404)));
        assert!(!authentication_failure(&Error::Connection("closed")));
        assert!(authentication_code("RelayHttp401"));
        assert!(authentication_code(
            "Expected HTTP 101 response but was '403 Forbidden'"
        ));
        assert_eq!(retry(true, 8, 500), Retry::Stop);
        assert_eq!(retry(false, 0, 0), Retry::After(1));
        assert_eq!(retry(false, 1, 3), Retry::After(2));
        assert_eq!(retry(false, 16, 3), Retry::After(30));
        assert_eq!(
            retry(false, 30, STABLE_CONNECTION_SECS - 1),
            Retry::After(30)
        );
        assert_eq!(retry(false, 30, STABLE_CONNECTION_SECS), Retry::After(1));
    }

    #[test]
    fn fresh_identities_differ() {
        let (a, b) = (fresh_identity().unwrap(), fresh_identity().unwrap());
        assert_ne!(a.device, b.device);
        assert_ne!(a.secret, b.secret);
        assert_eq!(a.device.len(), 36);
        assert_eq!(a.public_key.len(), 64);
    }
}
