import { randomBytes } from 'node:crypto';
import nacl from 'tweetnacl';
import WebSocket from 'ws';
import type { Journal } from './journal.js';
import { DecryptStream, EncryptStream, RECORD_PLAINTEXT, decodeFrame, encodeFrame, parseDescriptor, recordAAD } from './stream-crypto.js';

export { Journal, RETENTION_SECONDS, CLEANUP_BATCH } from './journal.js';
export type { JournalOptions, OutboxRecord, OutboxStatus } from './journal.js';
export { DecryptStream, EncryptStream, RECORD_PLAINTEXT, recordAAD, encodeFrame, decodeFrame } from './stream-crypto.js';
export type { StreamDescriptor } from './stream-crypto.js';
export { Files, prepareFile, decryptFile, safeFileName } from './files.js';
export type { FileInfo, FileStatus, FilesOptions } from './files.js';

type ObjectValue = Record<string, unknown>;
export type EnvelopeKind = 'message' | 'stream.open' | 'stream.accept' | 'file';
const decoder = new TextDecoder('utf-8', { fatal: true });
const objectID = /^[a-f0-9]{32}$/;
const kinds: readonly string[] = ['message', 'stream.open', 'stream.accept', 'file'];
function object(value: unknown): ObjectValue {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid object');
  return value as ObjectValue;
}
function key(hex: string): Uint8Array {
  if (!/^[a-f0-9]{64}$/.test(hex)) throw new Error('Expected a 32-byte lowercase hex key');
  return Buffer.from(hex, 'hex');
}
function base64(text: unknown): Buffer {
  if (typeof text !== 'string' || text.length > 262144 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(text)) throw new Error('Invalid base64');
  const data = Buffer.from(text, 'base64');
  if (data.toString('base64') !== text) throw new Error('Noncanonical base64');
  return data;
}
const systemClock = () => Math.floor(Date.now() / 1000);

/** Device identity and pinned peer keys. Discovery never changes this trust map. */
export class Identity {
  readonly publicKey: string;
  readonly #secret: Uint8Array;
  readonly #trusted: Map<string, Uint8Array>;
  constructor(readonly app: string, readonly group: string, readonly device: string,
    secretKey: string, trustedPeers: Readonly<Record<string, string>>) {
    for (const name of [app, group, device]) if (!/^[A-Za-z0-9_-]{1,80}$/.test(name)) throw new Error('Invalid identity name');
    this.#secret = key(secretKey);
    this.publicKey = Buffer.from(nacl.box.keyPair.fromSecretKey(this.#secret).publicKey).toString('hex');
    this.#trusted = new Map(Object.entries(trustedPeers).map(([name, value]) => [name, key(value)]));
  }
  static generateKeyPair(): { secretKey: string; publicKey: string } {
    const pair = nacl.box.keyPair();
    return { secretKey: Buffer.from(pair.secretKey).toString('hex'), publicKey: Buffer.from(pair.publicKey).toString('hex') };
  }
  private context(from: string, to: string, kind: EnvelopeKind, id: string): unknown[] { return [1, this.app, this.group, from, to, kind, id]; }
  private peer(name: string): Uint8Array {
    const peer = this.#trusted.get(name);
    if (!peer) throw new Error('Untrusted peer');
    // Reject low-order public keys instead of accepting a publicly known shared key.
    if (nacl.scalarMult(this.#secret, peer).every(byte => byte === 0)) throw new Error('Invalid peer key');
    return peer;
  }
  /** Encrypts `{context,value}` for a pinned peer; the context binds app, group, both devices, kind and ID. */
  seal(to: string, kind: EnvelopeKind, id: string, value: ObjectValue): string {
    if (!objectID.test(id) || !kinds.includes(kind)) throw new Error('Invalid envelope ID or kind');
    const plain = Buffer.from(JSON.stringify({ context: this.context(this.device, to, kind, id), value }));
    const nonce = randomBytes(24);
    const body = Buffer.concat([nonce, nacl.box(plain, nonce, this.peer(to), this.#secret)]).toString('base64');
    if (body.length > 262144) throw new Error('Encrypted message exceeds 256 KiB');
    return body;
  }
  /** Authenticates an envelope from a pinned peer and returns its value after an exact context check. */
  open(from: string, kind: EnvelopeKind, id: string, body: string): ObjectValue {
    if (!objectID.test(id) || !kinds.includes(kind)) throw new Error('Invalid envelope ID or kind');
    const raw = base64(body);
    if (raw.length < 40) throw new Error('Truncated envelope');
    const plain = nacl.box.open(raw.subarray(24), raw.subarray(0, 24), this.peer(from), this.#secret);
    if (!plain) throw new Error('Envelope authentication failed');
    const parsed = object(JSON.parse(decoder.decode(plain)));
    if (JSON.stringify(parsed.context) !== JSON.stringify(this.context(from, this.device, kind, id))) throw new Error('Authenticated context mismatch');
    return object(parsed.value);
  }
  /** `expires` (absolute Unix seconds) is authenticated inside the envelope for offline messages. */
  sealMessage(to: string, id: string, data: Uint8Array, expires?: number): string {
    if (data.length > 192000) throw new Error('Invalid ID or message too large');
    const value: ObjectValue = { data: Buffer.from(data).toString('base64') };
    if (expires !== undefined) {
      if (!Number.isSafeInteger(expires) || expires <= 0) throw new Error('Invalid expiry');
      value.expires = expires;
    }
    return this.seal(to, 'message', id, value);
  }
  openMessage(from: string, id: string, body: string): Buffer {
    const value = this.open(from, 'message', id, body);
    if ('expires' in value && (!Number.isSafeInteger(value.expires) || (value.expires as number) <= Date.now() / 1000)) throw new Error('Expired message');
    return base64(value.data);
  }
}

export interface Peer { app: string; group: string; device: string; public_key: string }
/** `offline` messages must be acknowledged with Client.acknowledge after the application commits them. */
export interface Message { type: 'message'; id: string; from: string; data: Buffer; offline: boolean }
/** Incoming stream request: pass to acceptStream or rejectStream. Unaccepted requests expire after 40 s. */
export interface StreamRequest { type: 'stream.open'; id: string; from: string; body: string }
export interface Presence { type: 'peer.up' | 'peer.down' | 'group.changed'; [key: string]: unknown }
export type RelayEvent = Message | StreamRequest | Presence;
export interface ClientOptions {
  allowLocalTest?: boolean; timeoutMs?: number;
  /** Persistent journal required for offline send/receive. The caller owns and closes it. */
  journal?: Journal;
  /** Unix seconds; for tests. */
  clock?: () => number;
}
export interface MessageOptions { offline?: boolean; id?: string; ttl?: number }
/** forwarded: queued online; stored: persisted by the relay; received: acknowledged by the peer. */
export interface MessageReceipt { type: 'forwarded' | 'stored' | 'received'; id: string }
type Pending = { expected: readonly string[]; resolve: (event: ObjectValue) => void; reject: (error: Error) => void };
interface Transport { sendEvent(event: ObjectValue): void; sendBinary(frame: Buffer): void; forget(id: string): void }

/**
 * One direction pair of an accepted stream. Records are at most 65519 plaintext bytes, sequence-bound
 * and flow-controlled (at most 8 unconsumed). Applications needing a complete transfer must send and
 * check the FINAL record; close/disconnect is cancellation, never a reliable half-close.
 */
export class Stream {
  #decryptor?: DecryptStream;
  readonly #encryptor = new EncryptStream();
  readonly #queue: { sequence: number; cipher: Buffer }[] = [];
  #receiver?: { resolve: () => void; reject: (error: Error) => void };
  #credit?: { resolve: () => void; reject: (error: Error) => void };
  #sendChain: Promise<void> = Promise.resolve();
  #tx = 0; #rx = 0; #acknowledged = 0;
  #closed = false;
  #failure?: Error;
  /** @internal */
  constructor(private readonly identity: Identity, private readonly transport: Transport, readonly peer: string, readonly id: string) {}
  /** @internal */ get descriptor() { return this.#encryptor.descriptor; }
  /** @internal */ set decryptor(value: DecryptStream) { this.#decryptor = value; }
  get receivedFinal(): boolean { return this.#decryptor?.finished ?? false; }
  get sentFinal(): boolean { return this.#encryptor.finished; }
  get closed(): boolean { return this.#closed; }

  /** Sends data as one or more records; `final` marks the last record FINAL. Calls are serialized. */
  send(data: Uint8Array, final = false): Promise<void> {
    const run = this.#sendChain.then(() => this.#send(data, final));
    this.#sendChain = run.catch(() => undefined);
    return run;
  }
  async #send(data: Uint8Array, final: boolean): Promise<void> {
    for (let offset = 0; offset < Math.max(1, data.length); offset += RECORD_PLAINTEXT) {
      if (this.#closed) throw this.#failure!;
      if (this.#tx - this.#acknowledged >= 8) await this.#waitCredit();
      if (this.#closed) throw this.#failure!;
      const end = Math.min(data.length, offset + RECORD_PLAINTEXT);
      const aad = recordAAD(this.identity.app, this.identity.group, this.identity.device, this.peer, 'stream', this.id, this.#tx);
      const cipher = this.#encryptor.push(data.subarray(offset, end), aad, final && end === data.length);
      this.transport.sendBinary(encodeFrame(this.id, this.#tx, cipher));
      this.#tx++;
    }
  }
  #waitCredit(): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.close(new Error('Stream credit timeout')), 30000);
      this.#credit = { resolve: () => { clearTimeout(timer); resolve(); }, reject: error => { clearTimeout(timer); reject(error); } };
    });
  }
  /** Returns the next authenticated record in order; check receivedFinal afterwards. */
  async receive(): Promise<Buffer> {
    if (this.#closed) throw this.#failure!;
    if (this.#receiver) throw new Error('Concurrent stream receive');
    if (!this.#queue.length) await new Promise<void>((resolve, reject) => { this.#receiver = { resolve, reject }; }).finally(() => { this.#receiver = undefined; });
    const item = this.#queue.shift()!;
    let plain: Buffer;
    try {
      if (!this.#decryptor || item.sequence !== this.#rx) throw new Error('Invalid stream sequence or state');
      plain = this.#decryptor.pull(item.cipher, recordAAD(this.identity.app, this.identity.group, this.peer, this.identity.device, 'stream', this.id, this.#rx));
    } catch (error) {
      this.close();
      throw error;
    }
    this.#rx++;
    this.transport.sendEvent({ type: 'stream.credit', id: this.id, sequence: this.#rx });
    return plain;
  }
  /** Cancels the stream locally and at the relay; nothing is resumed or replayed. */
  close(reason = new Error('Stream closed')): void {
    if (this.#closed) return;
    this.abort(reason);
    try { this.transport.sendEvent({ type: 'stream.close', id: this.id }); } catch { /* connection already gone */ }
  }
  /** @internal */
  enqueue(sequence: number, cipher: Buffer): void {
    if (this.#closed) return;
    if (this.#queue.length >= 16) { this.close(); return; }
    this.#queue.push({ sequence, cipher });
    this.#receiver?.resolve();
  }
  /** @internal */
  credit(sequence: unknown): void {
    if (!Number.isSafeInteger(sequence) || (sequence as number) < this.#acknowledged || (sequence as number) > this.#tx) throw new Error('Invalid stream credit');
    this.#acknowledged = sequence as number;
    if (this.#tx - this.#acknowledged < 8 && this.#credit) { const waiter = this.#credit; this.#credit = undefined; waiter.resolve(); }
  }
  /** @internal */
  abort(error = new Error('Stream interrupted; do not replay operations')): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#failure = error;
    this.#queue.length = 0;
    this.#receiver?.reject(error);
    this.#credit?.reject(error); this.#credit = undefined;
    this.transport.forget(this.id);
  }
}

/** One explicit connection lifetime. Online sends and streams are never replayed automatically. */
export class Client {
  readonly #pending = new Map<string, Pending>();
  readonly #streams = new Map<string, Stream>();
  readonly #events: RelayEvent[] = [];
  readonly #journal?: Journal;
  readonly #clock: () => number;
  readonly #scope: string;
  readonly #transport: Transport;
  #cleaner?: NodeJS.Timeout;
  #waiter?: { resolve: (event: RelayEvent) => void; reject: (error: Error) => void };
  #failure?: Error;
  #welcomed = false;
  private constructor(readonly identity: Identity, private socket: WebSocket, private timeoutMs: number, options: ClientOptions) {
    this.#journal = options.journal;
    this.#clock = options.clock ?? systemClock;
    this.#scope = JSON.stringify([identity.app, identity.group, identity.device]);
    this.#transport = {
      sendEvent: event => this.send(event),
      sendBinary: frame => this.sendBinary(frame),
      forget: id => { this.#streams.delete(id); },
    };
  }

  static async connect(url: string, token: string, identity: Identity, options: ClientOptions = {}): Promise<Client> {
    const endpoint = new URL(url);
    const local = options.allowLocalTest === true && endpoint.protocol === 'ws:' && endpoint.hostname === '127.0.0.1';
    if ((endpoint.protocol !== 'wss:' && !local) || endpoint.username || endpoint.password || endpoint.hash || endpoint.search || endpoint.pathname !== '/relay/v1/ws') throw new Error('A WSS relay endpoint is required');
    if (!/^[A-Za-z0-9_-]{32,256}$/.test(token)) throw new Error('Invalid device credential');
    const timeout = options.timeoutMs ?? 45000;
    if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 120000) throw new Error('Invalid timeout');
    const ws = new WebSocket(endpoint, 'common-relay.v1', {
      headers: { Authorization: `Bearer ${token}` }, perMessageDeflate: false,
      followRedirects: false, handshakeTimeout: timeout, maxPayload: 1 << 20,
    });
    const client = new Client(identity, ws, timeout, options);
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => client.fail(new Error('Welcome timeout')), timeout);
      const stop = (error: Error) => { clearTimeout(timer); reject(error); };
      ws.on('error', () => { const error = new Error('Relay transport failed'); client.fail(error); stop(error); });
      ws.on('close', () => { const error = new Error('Relay connection closed'); client.fail(error); stop(error); });
      ws.on('message', (raw, binary) => {
        try {
          if (!client.#welcomed) {
            if (binary) throw new Error('Binary frame before welcome');
            const event = object(JSON.parse(decoder.decode(Buffer.from(raw as Buffer))));
            const own = object(event.identity);
            if (ws.protocol !== 'common-relay.v1' || event.type !== 'welcome' || event.version !== 1 || own.app !== identity.app || own.group !== identity.group || own.device !== identity.device || own.public_key !== identity.publicKey) throw new Error('Welcome identity or protocol mismatch');
            client.#welcomed = true; clearTimeout(timer);
            client.startCleaner();
            resolve();
          } else if (binary) client.dispatchBinary(Buffer.from(raw as Buffer));
          else client.dispatch(object(JSON.parse(decoder.decode(Buffer.from(raw as Buffer)))));
        } catch (error) { const failure = error instanceof Error ? error : new Error('Invalid relay event'); client.fail(failure); stop(failure); }
      });
    });
    return client;
  }

  private startCleaner(): void {
    if (!this.#journal) return;
    this.#cleaner = setInterval(() => {
      // Never keep sending when durable state can no longer be maintained.
      try { this.#journal!.cleanup(); } catch (error) { this.fail(error instanceof Error ? error : new Error('Journal cleanup failed')); }
    }, 3600_000);
    this.#cleaner.unref();
  }
  private fail(error: Error): void {
    if (this.#failure) return;
    this.#failure = error;
    clearInterval(this.#cleaner);
    this.#events.length = 0;
    for (const pending of this.#pending.values()) pending.reject(error);
    this.#pending.clear(); this.#waiter?.reject(error); this.#waiter = undefined;
    for (const stream of [...this.#streams.values()]) stream.abort();
    this.#streams.clear();
    this.socket.terminate();
  }
  /** Closes the connection. A supplied journal stays open for reuse by the next connection. */
  close(): void { this.fail(new Error('Client closed')); }
  /** Explicit journal cleanup round (at most 256 changes); returns the number of changes. */
  cleanup(): number { return this.#journal?.cleanup() ?? 0; }
  private ensureWritable(): void {
    if (this.#failure) throw this.#failure;
    if (!this.#welcomed || this.socket.readyState !== WebSocket.OPEN || this.socket.bufferedAmount > 4 << 20) throw new Error('Connection unavailable or backpressure');
  }
  private send(event: ObjectValue): void {
    this.ensureWritable();
    this.socket.send(JSON.stringify(event), error => { if (error) this.fail(new Error('Relay write failed')); });
  }
  private sendBinary(frame: Buffer): void {
    this.ensureWritable();
    this.socket.send(frame, { binary: true }, error => { if (error) this.fail(new Error('Relay write failed')); });
  }
  private async request(event: ObjectValue, expected: string): Promise<ObjectValue> {
    const id = randomBytes(16).toString('hex');
    event.id = id;
    return this.requestWithID(event, [expected], id);
  }
  private async requestWithID(event: ObjectValue, expected: readonly string[], id: string): Promise<ObjectValue> {
    if (this.#pending.size >= 64) throw new Error('Too many pending requests');
    if (this.#pending.has(id)) throw new Error('Request already pending');
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => finish(new Error('Relay request timed out')), this.timeoutMs);
      const finish = (error?: Error, result?: ObjectValue) => {
        clearTimeout(timer); this.#pending.delete(id);
        if (error) reject(error); else resolve(result!);
      };
      this.#pending.set(id, { expected, resolve: result => finish(undefined, result), reject: error => finish(error) });
      try { this.send(event); } catch (error) { finish(error as Error); }
    });
  }
  async peers(): Promise<Peer[]> {
    const event = await this.request({ type: 'peers' }, 'peers');
    if (event.devices === undefined || event.devices === null) return [];
    if (!Array.isArray(event.devices)) throw new Error('Invalid peer list');
    return event.devices.map(value => {
      const peer = object(value);
      if (peer.app !== this.identity.app || peer.group !== this.identity.group || typeof peer.device !== 'string' || typeof peer.public_key !== 'string') throw new Error('Invalid peer scope');
      key(peer.public_key);
      return peer as unknown as Peer;
    });
  }
  /**
   * Online (default): `forwarded` means queued by the relay, not delivered or processed by the peer.
   * Offline: requires a journal. Persist the application's message ID and retry with the same ID;
   * the original ciphertext and fixed absolute expiry (default 24 h) are reused. `stored` means the
   * relay persisted it; `received` means the peer acknowledged it.
   */
  async message(to: string, data: Uint8Array, options: MessageOptions = {}): Promise<MessageReceipt> {
    const id = options.id ?? randomBytes(16).toString('hex');
    if (!objectID.test(id)) throw new Error('Invalid message ID');
    if (!options.offline) {
      const body = this.identity.sealMessage(to, id, data);
      await this.requestWithID({ type: 'message', id, to, body, offline: false }, ['forwarded'], id);
      return { type: 'forwarded', id };
    }
    const journal = this.#journal;
    if (!journal) throw new Error('Persistent journal required for offline delivery');
    if (this.#failure) throw this.#failure;
    const record = journal.prepare(this.#scope, id, to, data, options.ttl ?? 86400, expires => this.identity.sealMessage(to, id, data, expires));
    if (record.status === 'received') return { type: 'received', id };
    const ttl = record.expires - this.#clock();
    if (ttl < 1) throw new Error('Message expired');
    const result = await this.requestWithID({ type: 'message', id, to, body: record.body, offline: true, ttl, expires: record.expires }, ['stored', 'received'], id);
    if (result.type === 'received') journal.complete(this.#scope, id);
    return { type: result.type as 'stored' | 'received', id };
  }
  /**
   * Call only AFTER the application's durable transaction succeeds. The dedupe record is persisted
   * before the ACK is sent, so a redelivery after a lost ACK is re-acknowledged, not redelivered.
   */
  async acknowledge(event: Pick<Message, 'id' | 'from'> & { offline?: boolean }): Promise<void> {
    if (event.offline && !this.#journal) throw new Error('Persistent journal required for offline acknowledgment');
    if (!objectID.test(event.id) || typeof event.from !== 'string') throw new Error('Invalid message event');
    this.#journal?.acknowledge(this.#scope, event.from, event.id);
    if (event.offline) await this.requestWithID({ type: 'ack', id: event.id, from: event.from }, ['acked'], event.id);
  }
  async openStream(to: string): Promise<Stream> {
    const id = randomBytes(16).toString('hex');
    const stream = new Stream(this.identity, this.#transport, to, id);
    const body = this.identity.seal(to, 'stream.open', id, { ...stream.descriptor });
    this.#streams.set(id, stream);
    try {
      const reply = await this.requestWithID({ type: 'stream.open', id, to, body }, ['stream.accept'], id);
      if (reply.from !== undefined && reply.from !== to) throw new Error('Stream accept from unexpected peer');
      if (typeof reply.body !== 'string') throw new Error('Invalid stream accept');
      stream.decryptor = new DecryptStream(parseDescriptor(this.identity.open(to, 'stream.accept', id, reply.body)));
      if (stream.closed) throw new Error('Stream closed');
      return stream;
    } catch (error) { stream.close(); throw error; }
  }
  async acceptStream(event: StreamRequest): Promise<Stream> {
    if (event.type !== 'stream.open' || this.#streams.has(event.id)) throw new Error('Invalid stream request');
    const decryptor = new DecryptStream(parseDescriptor(this.identity.open(event.from, 'stream.open', event.id, event.body)));
    const stream = new Stream(this.identity, this.#transport, event.from, event.id);
    stream.decryptor = decryptor;
    this.#streams.set(event.id, stream);
    try {
      await this.requestWithID({ type: 'stream.accept', id: event.id, body: this.identity.seal(event.from, 'stream.accept', event.id, { ...stream.descriptor }) }, ['stream.ready'], event.id);
      if (stream.closed) throw new Error('Stream closed');
      return stream;
    } catch (error) { stream.close(); throw error; }
  }
  rejectStream(event: StreamRequest): void { this.send({ type: 'stream.close', id: event.id }); }
  /** A single consumer, bounded to 64 events; cancellation removes only this wait. */
  async nextEvent(signal?: AbortSignal): Promise<RelayEvent> {
    if (signal?.aborted) throw new Error('Event wait cancelled');
    if (this.#failure) throw this.#failure;
    if (this.#waiter) throw new Error('Concurrent event receive');
    const queued = this.#events.shift();
    if (queued) return queued;
    return new Promise((resolve, reject) => {
      const cleanup = () => { signal?.removeEventListener('abort', cancel); this.#waiter = undefined; };
      const cancel = () => { cleanup(); reject(new Error('Event wait cancelled')); };
      this.#waiter = { resolve: event => { cleanup(); resolve(event); }, reject: error => { cleanup(); reject(error); } };
      signal?.addEventListener('abort', cancel, { once: true });
    });
  }
  private dispatchBinary(raw: Buffer): void {
    const frame = decodeFrame(raw);
    this.#streams.get(frame.id)?.enqueue(frame.sequence, Buffer.from(frame.cipher));
  }
  private dispatch(event: ObjectValue): void {
    if (event.type === 'welcome') throw new Error('Repeated welcome');
    const id = typeof event.id === 'string' ? event.id : undefined;
    let output: RelayEvent;
    if (event.type === 'stream.credit') {
      if (id) this.#streams.get(id)?.credit(event.sequence);
      return;
    }
    if (event.type === 'stream.close') {
      if (!id) return;
      this.#streams.get(id)?.abort();
      this.#pending.get(id)?.reject(new Error('Stream closed'));
      return;
    }
    if (event.type === 'message') {
      const offline = event.offline === true;
      if (offline && !this.#journal) throw new Error('Offline reception requires a persistent journal');
      if (typeof event.from !== 'string' || !id || !objectID.test(id) || typeof event.body !== 'string') throw new Error('Invalid message');
      const value = this.identity.open(event.from, 'message', id, event.body);
      if ('expires' in value && !Number.isSafeInteger(value.expires)) throw new Error('Invalid message expiry');
      // Expired or already acknowledged: re-ACK an offline redelivery without passing it to the app.
      if (('expires' in value && (value.expires as number) <= this.#clock()) || this.#journal?.contains(this.#scope, event.from, id)) {
        if (offline) this.send({ type: 'ack', id, from: event.from });
        return;
      }
      output = { type: 'message', from: event.from, id, data: base64(value.data), offline };
    } else if (event.type === 'stream.open') {
      if (!id || !objectID.test(id) || typeof event.from !== 'string' || typeof event.body !== 'string') throw new Error('Invalid stream request');
      output = { type: 'stream.open', id, from: event.from, body: event.body };
    } else if (['peer.up', 'peer.down', 'group.changed'].includes(String(event.type))) {
      output = event as Presence;
    } else {
      const pending = id ? this.#pending.get(id) : undefined;
      if (pending) {
        if (event.type === 'error') pending.reject(new Error(`Relay error: ${String(event.code)}`));
        else if (!pending.expected.includes(String(event.type))) pending.reject(new Error('Unexpected reply type'));
        else pending.resolve(event);
      } else if (event.type === 'error' && id) this.#streams.get(id)?.abort(new Error(`Relay error: ${String(event.code)}`));
      return;
    }
    if (this.#waiter) this.#waiter.resolve(output);
    else { if (this.#events.length >= 64) throw new Error('Event receive overflow'); this.#events.push(output); }
  }
}

export { Groups, advance, validateState, validateGrant } from './groups.js';
export type { GroupObject, GroupEntry } from './groups.js';
export * from './invitation-links.js';
