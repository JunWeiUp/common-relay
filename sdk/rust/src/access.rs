//! Server access password and endpoint validation shared by groups and files.
use url::Url;

use crate::{Error, Result};

/// Header carrying the server-wide access password on every `/v2` request.
pub const ACCESS_HEADER: &str = "Relay-Access";

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Options {
    pub allow_local_test: bool,
    /// Server access password (8-128 printable ASCII, no spaces), sent as `Relay-Access`
    /// on every HTTP request. Required by production relays.
    pub password: Option<String>,
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("allow_local_test", &self.allow_local_test)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// 8..=128 bytes, each printable ASCII 0x21..=0x7e.
pub(crate) fn valid_access_password(p: &str) -> bool {
    (8..=128).contains(&p.len()) && p.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Validates an optional access password; `None` means no header is sent.
pub(crate) fn checked_access_password(p: Option<&str>) -> Result<Option<&str>> {
    match p {
        Some(p) if !valid_access_password(p) => Err(Error::Invalid(
            "access password must be 8-128 printable ASCII characters without spaces",
        )),
        other => Ok(other),
    }
}

/// Accepts only `wss://host/v2/ws` (or `ws://127.0.0.1/v2/ws` for local tests).
pub(crate) fn validate_endpoint(endpoint: &str, options: &Options) -> Option<Url> {
    let u = Url::parse(endpoint).ok()?;
    let local = options.allow_local_test && u.scheme() == "ws" && u.host_str() == Some("127.0.0.1");
    let valid = (u.scheme() == "wss" || local)
        && u.host_str().is_some_and(|h| !h.is_empty())
        && u.username().is_empty()
        && u.password().is_none()
        && u.query().is_none()
        && u.fragment().is_none()
        && u.path() == "/v2/ws";
    valid.then_some(u)
}

pub(crate) fn valid_token(token: &str) -> bool {
    (32..=256).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
