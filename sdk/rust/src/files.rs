//! Encrypted staged files and the `/relay/v1/files` HTTP API.
//! Ciphertext is `length[4, big-endian] | secretstream record` repeated, ending with FINAL.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, RANGE};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use url::Url;

use crate::client::{valid_token, validate_endpoint};
use crate::crypto::{random, valid_id, valid_name};
use crate::secretstream::{aad, DecryptStream, EncryptStream, ABYTES, MAX_RECORD_PLAIN};
use crate::{Error, Identity, Options, Result};

const CHUNK: usize = 1 << 20;
const MAX_JSON: usize = 4 << 20;
const MAX_FILE: u64 = 1 << 30;
const REQUEST_LIMIT: Duration = Duration::from_secs(60);

/// What the sender submits to `POST /relay/v1/files`; size and digest cover the ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDescriptor {
    pub id: String,
    pub to: String,
    pub size: u64,
    /// A `file` envelope carrying the secretstream key/header and encrypted metadata.
    pub metadata: String,
    pub sha256: String,
}

/// Relay status for one file object.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FileInfo {
    pub id: String,
    pub to: String,
    pub from: String,
    pub size: u64,
    pub offset: u64,
    pub metadata: String,
    pub sha256: String,
    pub state: String,
    pub expires: i64,
}

fn io(_: std::io::Error) -> Error {
    Error::Storage("file storage failed")
}

fn create_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(io)
}

fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        File::open(parent).and_then(|d| d.sync_all()).map_err(io)?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Fills `buffer` unless the reader ends first; returns the number of bytes read.
fn read_full(reader: &mut impl Read, buffer: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io(e)),
        }
    }
    Ok(filled)
}

fn file_digest(path: &Path) -> Result<(u64, String)> {
    let mut file = File::open(path).map_err(io)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0u8; CHUNK];
    let mut size = 0u64;
    loop {
        let n = read_full(&mut file, &mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
        size += n as u64;
    }
    Ok((size, hex::encode(hash.finalize())))
}

/// Encrypts `source` into a new private `staged` file for `to`; keep it to resume uploads.
/// `metadata` (for example `{"name": ...}`) is encrypted; it never appears in HTTP headers.
/// Blocking file I/O: call from `spawn_blocking` for large files.
pub fn prepare_file(
    identity: &Identity,
    to: &str,
    source: &Path,
    staged: &Path,
    metadata: Value,
) -> Result<FileDescriptor> {
    if !valid_name(to) {
        return Err(Error::Invalid("invalid recipient"));
    }
    let mut input = File::open(source).map_err(io)?;
    let id = hex::encode(random::<16>()?);
    let mut encryptor = EncryptStream::new()?;
    let mut descriptor = encryptor.descriptor();
    descriptor["metadata"] = metadata;
    let metadata = identity.seal_value(to, "file", &id, descriptor)?;
    let mut output = create_private(staged)?;
    let written = (|| {
        let mut hash = Sha256::new();
        let mut buffer = vec![0u8; MAX_RECORD_PLAIN];
        let mut size = 0u64;
        for sequence in 0u64.. {
            let n = read_full(&mut input, &mut buffer)?;
            let ad = aad(
                &identity.app,
                &identity.group,
                identity.device(),
                to,
                "file",
                &id,
                sequence,
            );
            // An empty FINAL record always ends the file, as in the other SDKs.
            let record = encryptor.push(&buffer[..n], &ad, n == 0)?;
            let mut framed = (record.len() as u32).to_be_bytes().to_vec();
            framed.extend_from_slice(&record);
            output.write_all(&framed).map_err(io)?;
            hash.update(&framed);
            size += framed.len() as u64;
            if n == 0 {
                break;
            }
        }
        output.sync_all().map_err(io)?;
        if size > MAX_FILE {
            return Err(Error::Invalid("file exceeds 1 GiB"));
        }
        Ok((size, hex::encode(hash.finalize())))
    })();
    match written {
        Ok((size, sha256)) => Ok(FileDescriptor {
            id,
            to: to.into(),
            size,
            metadata,
            sha256,
        }),
        Err(err) => {
            let _ = fs::remove_file(staged);
            Err(err)
        }
    }
}

/// Verifies and decrypts a fully downloaded `staged` file from `from` into `destination`,
/// returning the sender's metadata. The destination appears only after the digest, every
/// record and the FINAL tag verify, and an existing file is never replaced. Choose the
/// destination yourself; see [`safe_file_name`] for remote names. Blocking file I/O.
pub fn decrypt_file(
    identity: &Identity,
    from: &str,
    info: &FileInfo,
    staged: &Path,
    destination: &Path,
) -> Result<Value> {
    if !valid_id(&info.id) || (!info.from.is_empty() && info.from != from) {
        return Err(Error::Invalid("file sender mismatch"));
    }
    if !info.to.is_empty() && info.to != identity.device() {
        return Err(Error::Invalid("file recipient mismatch"));
    }
    let mut descriptor = identity.open_value(from, "file", &info.id, &info.metadata)?;
    let mut decryptor = DecryptStream::new(&descriptor)?;
    let (size, digest) = file_digest(staged)?;
    if size != info.size || digest != info.sha256 {
        return Err(Error::Crypto("ciphertext digest mismatch"));
    }
    let name = destination
        .file_name()
        .ok_or(Error::Invalid("invalid destination"))?
        .to_string_lossy()
        .into_owned();
    let temporary: PathBuf =
        destination.with_file_name(format!(".{name}.{}.partial", hex::encode(random::<16>()?)));
    let mut output = create_private(&temporary)?;
    let result = (|| {
        let mut input = File::open(staged).map_err(io)?;
        let mut record = vec![0u8; 65536];
        for sequence in 0u64.. {
            let mut prefix = [0u8; 4];
            match read_full(&mut input, &mut prefix)? {
                0 => break,
                4 => {}
                _ => return Err(Error::Crypto("truncated file record")),
            }
            let length = u32::from_be_bytes(prefix) as usize;
            if !(ABYTES..=65536).contains(&length) {
                return Err(Error::Crypto("invalid file record size"));
            }
            if read_full(&mut input, &mut record[..length])? != length {
                return Err(Error::Crypto("truncated file record"));
            }
            let ad = aad(
                &identity.app,
                &identity.group,
                from,
                identity.device(),
                "file",
                &info.id,
                sequence,
            );
            // Records after FINAL fail here.
            let plain = decryptor.pull(&record[..length], &ad)?;
            output.write_all(&plain).map_err(io)?;
        }
        if !decryptor.finished {
            return Err(Error::Crypto("missing authenticated final record"));
        }
        output.sync_all().map_err(io)?;
        // A hard link publishes atomically and fails instead of replacing an existing file.
        fs::hard_link(&temporary, destination).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Invalid("destination already exists")
            } else {
                io(e)
            }
        })?;
        sync_parent(destination)
    })();
    drop(output);
    let _ = fs::remove_file(&temporary);
    result?;
    Ok(descriptor
        .get_mut("metadata")
        .map(Value::take)
        .unwrap_or(Value::Null))
}

/// Reduces an untrusted remote file name to a safe single path component, or `None`.
/// Applications still choose the directory and must handle existing names.
pub fn safe_file_name(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next()?.trim();
    let base = base.trim_start_matches('.');
    let valid = !base.is_empty()
        && base.len() <= 255
        && !base
            .chars()
            .any(|c| c.is_control() || matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0'));
    valid.then(|| base.to_owned())
}

/// HTTP client for `/relay/v1/files`. Redirects are refused so the credential never moves.
pub struct RelayFiles {
    base: Url,
    http: reqwest::Client,
}

impl std::fmt::Debug for RelayFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayFiles")
            .field("base", &self.base.as_str())
            .finish_non_exhaustive()
    }
}

fn http_error(err: reqwest::Error) -> Error {
    if err.is_timeout() {
        Error::Timeout
    } else {
        Error::Connection("relay HTTP request failed")
    }
}

impl RelayFiles {
    /// `files_url` is `https://host/relay/v1/files`; plain http only for 127.0.0.1 local tests.
    pub fn new(files_url: &str, token: &str, options: Options) -> Result<Self> {
        let base = Url::parse(files_url).map_err(|_| Error::Invalid("invalid files URL"))?;
        let local = options.allow_local_test
            && base.scheme() == "http"
            && base.host_str() == Some("127.0.0.1");
        let valid = (base.scheme() == "https" || local)
            && base.host_str().is_some_and(|h| !h.is_empty())
            && base.username().is_empty()
            && base.password().is_none()
            && base.query().is_none()
            && base.fragment().is_none()
            && base.path() == "/relay/v1/files";
        if !valid {
            return Err(Error::Invalid("an HTTPS relay files URL is required"));
        }
        if !valid_token(token) {
            return Err(Error::Invalid("invalid device credential"));
        }
        let mut headers = HeaderMap::new();
        let mut auth = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| Error::Invalid("invalid device credential"))?;
        auth.set_sensitive(true);
        headers.insert(AUTHORIZATION, auth);
        let http = reqwest::Client::builder()
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!local)
            .no_proxy()
            .connect_timeout(Duration::from_secs(15))
            .timeout(REQUEST_LIMIT)
            .build()
            .map_err(|_| Error::Connection("HTTP client initialization failed"))?;
        Ok(Self { base, http })
    }

    /// Derives the files URL from the WebSocket relay endpoint used by [`crate::Client`].
    pub fn for_relay_endpoint(endpoint: &str, token: &str, options: Options) -> Result<Self> {
        let mut url = validate_endpoint(endpoint, options)
            .ok_or(Error::Invalid("a WSS relay endpoint is required"))?;
        let scheme = if url.scheme() == "wss" {
            "https"
        } else {
            "http"
        };
        url.set_scheme(scheme)
            .map_err(|_| Error::Invalid("invalid relay endpoint"))?;
        url.set_path("/relay/v1/files");
        Self::new(url.as_str(), token, options)
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}{suffix}", self.base)
    }

    async fn call(
        &self,
        method: Method,
        suffix: &str,
        body: Option<(Vec<u8>, &'static str)>,
        header: Option<(reqwest::header::HeaderName, String)>,
        limit: usize,
    ) -> Result<(StatusCode, Vec<u8>)> {
        let mut request = self.http.request(method, self.url(suffix));
        if let Some((body, kind)) = body {
            request = request.header(CONTENT_TYPE, kind).body(body);
        }
        if let Some((name, value)) = header {
            request = request.header(name, value);
        }
        let mut response = request.send().await.map_err(http_error)?;
        let status = response.status();
        let mut data = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(http_error)? {
            if data.len() + chunk.len() > limit {
                return Err(Error::Protocol("relay response too large"));
            }
            data.extend_from_slice(&chunk);
        }
        Ok((status, data))
    }

    async fn json<T: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        suffix: &str,
        body: Option<Vec<u8>>,
        expected: &[u16],
    ) -> Result<(u16, T)> {
        let (status, data) = self
            .call(
                method,
                suffix,
                body.map(|b| (b, "application/json")),
                None,
                MAX_JSON,
            )
            .await?;
        if !expected.contains(&status.as_u16()) {
            return Err(Error::Http(status.as_u16()));
        }
        let value =
            serde_json::from_slice(&data).map_err(|_| Error::Protocol("invalid relay JSON"))?;
        Ok((status.as_u16(), value))
    }

    /// Current relay status of a file you sent or will receive.
    pub async fn status(&self, id: &str) -> Result<FileInfo> {
        if !valid_id(id) {
            return Err(Error::Invalid("invalid file ID"));
        }
        Ok(self
            .json::<FileInfo>(Method::GET, &format!("/{id}"), None, &[200])
            .await?
            .1)
    }

    /// Uploads (or resumes) `staged` and commits it. A repeated ID is resumed only if the
    /// relay's descriptor matches exactly; chunks are at most 1 MiB at the relay's offset.
    pub async fn upload(&self, file: &FileDescriptor, staged: &Path) -> Result<FileInfo> {
        if !valid_id(&file.id) || file.size == 0 || file.size > MAX_FILE {
            return Err(Error::Invalid("invalid file descriptor"));
        }
        let body = serde_json::to_vec(file).expect("JSON value");
        let (status, data) = self
            .call(
                Method::POST,
                "",
                Some((body, "application/json")),
                None,
                MAX_JSON,
            )
            .await?;
        // 409: the ID exists; resume only if the relay holds exactly this descriptor.
        let info = match status.as_u16() {
            201 => serde_json::from_slice::<FileInfo>(&data)
                .map_err(|_| Error::Protocol("invalid relay JSON"))?,
            409 => self.status(&file.id).await?,
            other => return Err(Error::Http(other)),
        };
        if info.id != file.id
            || info.to != file.to
            || info.size != file.size
            || info.metadata != file.metadata
            || info.sha256 != file.sha256
        {
            return Err(Error::Invalid("file ID conflict"));
        }
        if info.offset > file.size {
            return Err(Error::Protocol("invalid upload offset"));
        }
        let mut offset = info.offset;
        if info.state != "ready" {
            let mut input = File::open(staged).map_err(io)?;
            if input.metadata().map_err(io)?.len() != file.size {
                return Err(Error::Invalid("staged file does not match descriptor"));
            }
            input.seek(SeekFrom::Start(offset)).map_err(io)?;
            let mut buffer = vec![0u8; CHUNK];
            while offset < file.size {
                let n = read_full(&mut input, &mut buffer)?;
                if n == 0 {
                    return Err(Error::Invalid("staged file truncated"));
                }
                let (status, data) = self
                    .call(
                        Method::PUT,
                        &format!("/{}/data", file.id),
                        Some((buffer[..n].to_vec(), "application/octet-stream")),
                        Some((
                            reqwest::header::HeaderName::from_static("upload-offset"),
                            offset.to_string(),
                        )),
                        MAX_JSON,
                    )
                    .await?;
                if status != StatusCode::OK {
                    return Err(Error::Http(status.as_u16()));
                }
                let next: FileInfo = serde_json::from_slice(&data)
                    .map_err(|_| Error::Protocol("invalid relay JSON"))?;
                if next.offset != offset + n as u64 || next.offset > file.size {
                    return Err(Error::Protocol("invalid upload progress"));
                }
                offset = next.offset;
            }
        }
        let (_, committed) = self
            .json::<FileInfo>(Method::POST, &format!("/{}/commit", file.id), None, &[200])
            .await?;
        if committed.id != file.id || committed.state != "ready" {
            return Err(Error::Protocol("invalid commit response"));
        }
        Ok(committed)
    }

    /// Ready, unexpired files addressed to this device.
    pub async fn inbox(&self) -> Result<Vec<FileInfo>> {
        Ok(self.json(Method::GET, "", None, &[200]).await?.1)
    }

    /// Downloads ciphertext into `staged`, resuming from its current length with 1 MiB ranges.
    pub async fn download(&self, info: &FileInfo, staged: &Path) -> Result<()> {
        if !valid_id(&info.id) || info.size == 0 || info.size > MAX_FILE {
            return Err(Error::Invalid("invalid file info"));
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut output = options.open(staged).map_err(io)?;
        let mut offset = output.metadata().map_err(io)?.len();
        if offset > info.size {
            return Err(Error::Invalid("staged file exceeds declared size"));
        }
        while offset < info.size {
            let end = (offset + CHUNK as u64).min(info.size) - 1;
            let wanted = (end - offset + 1) as usize;
            let (status, data) = self
                .call(
                    Method::GET,
                    &format!("/{}/data", info.id),
                    None,
                    Some((RANGE, format!("bytes={offset}-{end}"))),
                    wanted,
                )
                .await?;
            if status != StatusCode::PARTIAL_CONTENT {
                return Err(Error::Http(status.as_u16()));
            }
            if data.len() != wanted {
                return Err(Error::Protocol("invalid range download"));
            }
            output.write_all(&data).map_err(io)?;
            offset += data.len() as u64;
        }
        output.sync_all().map_err(io)
    }

    /// Cancels (sender) or acknowledges (recipient) a file; the relay deletes it.
    pub async fn delete(&self, id: &str) -> Result<()> {
        if !valid_id(id) {
            return Err(Error::Invalid("invalid file ID"));
        }
        let (status, _) = self
            .call(Method::DELETE, &format!("/{id}"), None, None, MAX_JSON)
            .await?;
        if status != StatusCode::NO_CONTENT {
            return Err(Error::Http(status.as_u16()));
        }
        Ok(())
    }
}
