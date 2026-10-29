//! Durable offline delivery state: one file per record, replaced atomically.
//! Records hold recipients, digests, ciphertext and deadlines, never tokens, keys or plaintext.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{now, random};
use crate::{Error, Result};

/// Terminal and dedupe records are kept this long.
pub const RETENTION: i64 = 7 * 86400;
/// Default and maximum offline validity.
pub const DEFAULT_TTL: i64 = 86400;
/// Maximum record changes per cleanup round.
pub const CLEANUP_BATCH: usize = 256;

const PENDING: &str = "pending";
const RECEIVED: &str = "received";
const EXPIRED: &str = "expired";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Record {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recipient: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires: Option<i64>,
    purge: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<String>,
}

pub(crate) enum Prepared {
    /// Send (or resend) exactly this ciphertext with this fixed absolute expiry.
    Send { body: String, expires: i64 },
    /// The recipient already acknowledged this ID.
    Received,
}

type Clock = Box<dyn Fn() -> i64 + Send + Sync>;

/// Private persistent journal. Only one instance may own a directory at a time,
/// enforced with an exclusive lock on `journal.lock` that is released on drop.
pub struct RelayJournal {
    directory: PathBuf,
    clock: Clock,
    io: Mutex<()>,
    _lock: File,
}

impl fmt::Debug for RelayJournal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayJournal")
            .field("directory", &self.directory)
            .finish_non_exhaustive()
    }
}

fn storage(_: std::io::Error) -> Error {
    Error::Storage("journal storage failed")
}

#[cfg(unix)]
fn private_options(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}
#[cfg(not(unix))]
fn private_options(_: &mut OpenOptions) {}

fn sync_directory(directory: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(directory)
        .and_then(|d| d.sync_all())
        .map_err(storage)?;
    #[cfg(not(unix))]
    let _ = directory;
    Ok(())
}

/// Writes `data` to a new private temporary file in `directory`, syncs and renames it over `target`.
pub(crate) fn atomic_replace(directory: &Path, target: &Path, data: &[u8]) -> Result<()> {
    let temporary = directory.join(format!(".{}.tmp", hex::encode(random::<16>()?)));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        private_options(&mut options);
        let mut file = options.open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        fs::rename(&temporary, target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(storage)?;
    sync_directory(directory)
}

fn record_name(name: &str) -> bool {
    name.len() == 69
        && name.ends_with(".json")
        && name[..64]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl RelayJournal {
    /// Opens (creating if needed) a private directory and runs one cleanup round.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_clock(directory, now)
    }

    /// As [`RelayJournal::open`] with an injected Unix-seconds clock, for tests.
    pub fn open_with_clock(
        directory: impl AsRef<Path>,
        clock: impl Fn() -> i64 + Send + Sync + 'static,
    ) -> Result<Self> {
        let directory = directory.as_ref().to_path_buf();
        fs::create_dir_all(&directory).map_err(storage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).map_err(storage)?;
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        private_options(&mut options);
        let lock = options
            .open(directory.join("journal.lock"))
            .map_err(storage)?;
        // flock-style locks also conflict between two handles in one process.
        match lock.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => {
                return Err(Error::Storage("journal directory is already in use"))
            }
            Err(fs::TryLockError::Error(e)) => return Err(storage(e)),
        }
        // Leftover temporaries are incomplete writes from a crash; the previous record is intact.
        for entry in fs::read_dir(&directory).map_err(storage)? {
            let entry = entry.map_err(storage)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with('.') && name.ends_with(".tmp") {
                fs::remove_file(entry.path()).map_err(storage)?;
            }
        }
        let journal = Self {
            directory,
            clock: Box::new(clock),
            io: Mutex::new(()),
            _lock: lock,
        };
        journal.cleanup()?;
        Ok(journal)
    }

    fn guard(&self) -> MutexGuard<'_, ()> {
        self.io.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn path(&self, scope: &str, kind: &str, peer: &str, id: &str) -> PathBuf {
        let key = serde_json::to_vec(&[scope, kind, peer, id]).expect("JSON value");
        self.directory
            .join(format!("{}.json", hex::encode(Sha256::digest(key))))
    }

    fn read(path: &Path) -> Result<Option<Record>> {
        match fs::read(path) {
            Ok(raw) => serde_json::from_slice(&raw)
                .map(Some)
                .map_err(|_| Error::Storage("corrupt journal record")),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(storage(e)),
        }
    }

    fn write(&self, path: &Path, record: &Record) -> Result<()> {
        let data = serde_json::to_vec(record).expect("JSON value");
        atomic_replace(&self.directory, path, &data)
    }

    /// Persists the first send attempt before any network use, or returns the original attempt.
    pub(crate) fn prepare(
        &self,
        scope: &str,
        id: &str,
        to: &str,
        data: &[u8],
        ttl: i64,
        seal: impl FnOnce(i64) -> Result<String>,
    ) -> Result<Prepared> {
        if !(1..=DEFAULT_TTL).contains(&ttl) {
            return Err(Error::Invalid("offline TTL must be 1..=86400 seconds"));
        }
        let _guard = self.guard();
        let path = self.path(scope, "out", "", id);
        let digest = hex::encode(Sha256::digest(data));
        let now = (self.clock)();
        if let Some(old) = Self::read(&path)? {
            if old.recipient.as_deref() != Some(to) || old.digest.as_deref() != Some(&digest) {
                return Err(Error::Invalid("message ID reused with different content"));
            }
            return match (old.status.as_deref(), old.body, old.expires) {
                (Some(RECEIVED), _, _) => Ok(Prepared::Received),
                (Some(PENDING), Some(body), Some(expires)) if expires > now => {
                    Ok(Prepared::Send { body, expires })
                }
                _ => Err(Error::Invalid("offline message expired")),
            };
        }
        let expires = now + ttl;
        let body = seal(expires)?;
        let record = Record {
            recipient: Some(to.into()),
            digest: Some(digest),
            body: Some(body.clone()),
            expires: Some(expires),
            purge: expires + RETENTION,
            status: Some(PENDING.into()),
        };
        self.write(&path, &record)?;
        Ok(Prepared::Send { body, expires })
    }

    /// Records the recipient's acknowledgement and drops the ciphertext.
    pub(crate) fn complete(&self, scope: &str, id: &str) -> Result<()> {
        let _guard = self.guard();
        let path = self.path(scope, "out", "", id);
        if let Some(mut record) = Self::read(&path)? {
            if record.status.as_deref() == Some(RECEIVED) {
                return Ok(());
            }
            record.body = None;
            record.status = Some(RECEIVED.into());
            record.purge = (self.clock)() + RETENTION;
            self.write(&path, &record)?;
        }
        Ok(())
    }

    /// Whether a message from `sender` was already acknowledged by the application.
    pub(crate) fn contains(&self, scope: &str, sender: &str, id: &str) -> Result<bool> {
        let _guard = self.guard();
        let record = Self::read(&self.path(scope, "in", sender, id))?;
        Ok(record.is_some_and(|r| r.purge > (self.clock)()))
    }

    /// Saves the dedupe record; repeated acknowledgements never extend it.
    pub(crate) fn acknowledge(&self, scope: &str, sender: &str, id: &str) -> Result<()> {
        let _guard = self.guard();
        let path = self.path(scope, "in", sender, id);
        let now = (self.clock)();
        if Self::read(&path)?.is_some_and(|r| r.purge > now) {
            return Ok(());
        }
        let record = Record {
            purge: now + RETENTION,
            ..Record::default()
        };
        self.write(&path, &record)
    }

    /// Expires overdue pending sends and purges old records, at most 256 changes per call.
    /// Returns the number of changes; call again while it returns 256.
    pub fn cleanup(&self) -> Result<usize> {
        let _guard = self.guard();
        let now = (self.clock)();
        let mut changed = 0;
        for entry in fs::read_dir(&self.directory).map_err(storage)? {
            if changed >= CLEANUP_BATCH {
                break;
            }
            let entry = entry.map_err(storage)?;
            if !record_name(&entry.file_name().to_string_lossy()) {
                continue;
            }
            let path = entry.path();
            let Some(mut record) = Self::read(&path)? else {
                continue;
            };
            if record.purge <= now {
                fs::remove_file(&path).map_err(storage)?;
                changed += 1;
            } else if record.status.as_deref() == Some(PENDING)
                && record.expires.is_none_or(|e| e <= now)
            {
                record.body = None;
                record.status = Some(EXPIRED.into());
                self.write(&path, &record)?;
                changed += 1;
            }
        }
        if changed > 0 {
            sync_directory(&self.directory)?;
        }
        Ok(changed)
    }
}
