//! Encrypted bidirectional streams with credit-based flow control.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, watch, Semaphore};
use tokio::time::timeout;

use crate::client::{closed_signal, Event, Link};
use crate::secretstream::{aad, DecryptStream, EncryptStream, MAX_RECORD_PLAIN};
use crate::{Error, Identity, Result};

/// Unconsumed records the peer may send before it waits for credit.
const WINDOW: usize = 8;
/// Records buffered locally; the relay already limits the peer to `WINDOW`.
const BUFFER: usize = 16;
const CREDIT_WAIT: Duration = Duration::from_secs(30);

/// State shared between a stream handle and the connection task.
pub(crate) struct StreamShared {
    incoming: mpsc::Sender<(u64, Vec<u8>)>,
    credit: Semaphore,
    sent: AtomicU64,
    acknowledged: Mutex<u64>,
    closed: watch::Sender<bool>,
}

impl StreamShared {
    pub(crate) fn new() -> (Arc<Self>, mpsc::Receiver<(u64, Vec<u8>)>) {
        let (incoming, receiver) = mpsc::channel(BUFFER);
        let shared = Self {
            incoming,
            credit: Semaphore::new(WINDOW),
            sent: AtomicU64::new(0),
            acknowledged: Mutex::new(0),
            closed: watch::channel(false).0,
        };
        (Arc::new(shared), receiver)
    }

    /// Queues a received record; false means the peer overran the window.
    pub(crate) fn deliver(&self, sequence: u64, record: Vec<u8>) -> bool {
        self.is_closed() || self.incoming.try_send((sequence, record)).is_ok()
    }

    /// Applies a cumulative `stream.credit`; it must be monotonic and cover only sent records.
    pub(crate) fn credit(&self, sequence: u64) -> Result<()> {
        let mut acknowledged = self.acknowledged.lock().unwrap_or_else(|e| e.into_inner());
        if sequence < *acknowledged || sequence > self.sent.load(Ordering::SeqCst) {
            return Err(Error::Protocol("invalid stream credit"));
        }
        self.credit.add_permits((sequence - *acknowledged) as usize);
        *acknowledged = sequence;
        Ok(())
    }

    pub(crate) fn abort(&self) {
        self.closed.send_replace(true);
        self.credit.close();
    }

    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }
}

struct Receiving {
    incoming: mpsc::Receiver<(u64, Vec<u8>)>,
    decryptor: DecryptStream,
    next: u64,
}

/// One accepted stream. `send` and `receive` may run concurrently from different tasks.
/// Interruption is not a reliable half-close: verify [`RelayStream::received_final`].
pub struct RelayStream {
    id: String,
    peer: String,
    identity: Arc<Identity>,
    link: Link,
    shared: Arc<StreamShared>,
    sender: tokio::sync::Mutex<EncryptStream>,
    receiver: tokio::sync::Mutex<Receiving>,
    received_final: AtomicBool,
}

impl fmt::Debug for RelayStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayStream")
            .field("id", &self.id)
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl RelayStream {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        id: String,
        peer: String,
        identity: Arc<Identity>,
        link: Link,
        shared: Arc<StreamShared>,
        incoming: mpsc::Receiver<(u64, Vec<u8>)>,
        encryptor: EncryptStream,
        decryptor: DecryptStream,
    ) -> Self {
        Self {
            id,
            peer,
            identity,
            link,
            shared,
            sender: tokio::sync::Mutex::new(encryptor),
            receiver: tokio::sync::Mutex::new(Receiving {
                incoming,
                decryptor,
                next: 0,
            }),
            received_final: AtomicBool::new(false),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn peer(&self) -> &str {
        &self.peer
    }

    /// Whether the peer's authenticated FINAL record has been received.
    pub fn received_final(&self) -> bool {
        self.received_final.load(Ordering::SeqCst)
    }

    fn aad(&self, sender: &str, recipient: &str, sequence: u64) -> Vec<u8> {
        aad(
            &self.identity.app,
            &self.identity.group,
            sender,
            recipient,
            "stream",
            &self.id,
            sequence,
        )
    }

    /// Encrypts `data` as one or more records of at most 65519 bytes, waiting for credit.
    /// With `final_record`, the last record carries the FINAL tag and nothing may follow.
    pub async fn send(&self, data: &[u8], final_record: bool) -> Result<()> {
        let mut encryptor = self.sender.lock().await;
        if encryptor.finished {
            return Err(Error::Invalid("stream already sent its final record"));
        }
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![data]
        } else {
            data.chunks(MAX_RECORD_PLAIN).collect()
        };
        let last = chunks.len() - 1;
        for (index, chunk) in chunks.into_iter().enumerate() {
            match timeout(CREDIT_WAIT, self.shared.credit.acquire()).await {
                Ok(Ok(permit)) => permit.forget(),
                Ok(Err(_)) => return Err(Error::Connection("stream interrupted")),
                Err(_) => return Err(Error::Timeout),
            }
            if self.shared.is_closed() {
                return Err(Error::Connection("stream interrupted"));
            }
            let sequence = self.shared.sent.load(Ordering::SeqCst);
            let ad = self.aad(self.identity.device(), &self.peer, sequence);
            let record = encryptor.push(chunk, &ad, final_record && index == last)?;
            let mut frame = Vec::with_capacity(25 + record.len());
            frame.push(1);
            frame.extend_from_slice(&hex::decode(&self.id).expect("stream ID"));
            frame.extend_from_slice(&sequence.to_be_bytes());
            frame.extend_from_slice(&record);
            // Count the record before it is written so an immediate credit is in range.
            self.shared.sent.store(sequence + 1, Ordering::SeqCst);
            self.link.send_frame(frame).await?;
        }
        Ok(())
    }

    /// Receives, authenticates and consumes the next record in order, then grants credit.
    /// Reordered, duplicated, tampered or post-FINAL records abort the stream.
    pub async fn receive(&self) -> Result<Vec<u8>> {
        let mut receiving = self.receiver.lock().await;
        if receiving.decryptor.finished {
            return Err(Error::Invalid("stream already received its final record"));
        }
        let mut closed = self.shared.closed.subscribe();
        let item = tokio::select! {
            biased;
            _ = closed_signal(&mut closed) => None,
            item = receiving.incoming.recv() => item,
        };
        let Some((sequence, record)) = item else {
            return Err(Error::Connection("stream interrupted"));
        };
        let expected = receiving.next;
        let plain = if sequence != expected {
            Err(Error::Protocol("invalid stream sequence"))
        } else {
            let ad = self.aad(&self.peer, self.identity.device(), expected);
            receiving.decryptor.pull(&record, &ad)
        };
        let plain = match plain {
            Ok(plain) => plain,
            Err(err) => {
                self.abort_and_notify();
                return Err(err);
            }
        };
        receiving.next += 1;
        if receiving.decryptor.finished {
            self.received_final.store(true, Ordering::SeqCst);
        }
        let credit = Event {
            sequence: receiving.next,
            ..Event::request("stream.credit", self.id.clone())
        };
        self.link.send_event(&credit).await?;
        Ok(plain)
    }

    fn abort_and_notify(&self) {
        if !self.shared.is_closed() {
            self.link.remove_stream(&self.id);
            self.link
                .try_send_event(&Event::request("stream.close", self.id.clone()));
        }
    }

    /// Closes both directions. Unacknowledged records are not replayed.
    pub async fn close(&self) -> Result<()> {
        if self.shared.is_closed() {
            self.link.remove_stream(&self.id);
            return Ok(());
        }
        self.link.remove_stream(&self.id);
        if self.link.is_failed() {
            return Ok(());
        }
        self.link
            .send_event(&Event::request("stream.close", self.id.clone()))
            .await
    }
}

/// Dropping after both FINAL records only releases local state, so the peer can still read
/// buffered records and close; otherwise dropping closes the stream for both ends.
impl Drop for RelayStream {
    fn drop(&mut self) {
        if self.sender.get_mut().finished && self.received_final() {
            self.link.remove_stream(&self.id);
        } else {
            self.abort_and_notify();
        }
    }
}
