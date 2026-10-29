import sodium from 'libsodium-wrappers';

await sodium.ready;

/** Maximum plaintext per secretstream record (stream frames and file records). */
export const RECORD_PLAINTEXT = 65519;
const ABYTES = sodium.crypto_secretstream_xchacha20poly1305_ABYTES;
const TAG_MESSAGE = sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
const TAG_FINAL = sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;

export interface StreamDescriptor { key: string; header: string }
type State = ReturnType<typeof sodium.crypto_secretstream_xchacha20poly1305_init_push>['state'];

/** UTF-8 JSON array without whitespace: [1,app,group,sender,recipient,kind,id,sequence]. */
export function recordAAD(app: string, group: string, sender: string, recipient: string,
  kind: 'stream' | 'file', id: string, sequence: number): Buffer {
  if (!Number.isSafeInteger(sequence) || sequence < 0) throw new Error('Invalid record sequence');
  return Buffer.from(JSON.stringify([1, app, group, sender, recipient, kind, id, sequence]));
}

export function parseDescriptor(value: unknown): StreamDescriptor {
  const item = value as Record<string, unknown> | null;
  if (!item || typeof item !== 'object' || typeof item.key !== 'string' || typeof item.header !== 'string'
    || !/^[a-f0-9]{64}$/.test(item.key) || !/^[a-f0-9]{48}$/.test(item.header)) throw new Error('Invalid stream descriptor');
  return { key: item.key, header: item.header };
}

/** One direction of an xchacha20poly1305 secretstream with a fresh random key. */
export class EncryptStream {
  readonly descriptor: StreamDescriptor;
  #state: State;
  #finished = false;
  constructor() {
    const key = sodium.crypto_secretstream_xchacha20poly1305_keygen();
    const { state, header } = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
    this.#state = state;
    this.descriptor = { key: Buffer.from(key).toString('hex'), header: Buffer.from(header).toString('hex') };
    key.fill(0);
  }
  get finished(): boolean { return this.#finished; }
  push(data: Uint8Array, aad: Uint8Array, final = false): Buffer {
    if (this.#finished) throw new Error('Stream already finished');
    if (data.length > RECORD_PLAINTEXT) throw new Error('Record too large');
    const cipher = sodium.crypto_secretstream_xchacha20poly1305_push(this.#state, data, aad, final ? TAG_FINAL : TAG_MESSAGE);
    this.#finished = final;
    return Buffer.from(cipher.buffer, cipher.byteOffset, cipher.byteLength);
  }
}

/** Rejects tampering, reordering (via AAD sequence), unknown tags and records after FINAL. */
export class DecryptStream {
  #state: State;
  #finished = false;
  constructor(descriptor: StreamDescriptor) {
    const parsed = parseDescriptor(descriptor);
    const key = Buffer.from(parsed.key, 'hex');
    this.#state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(Buffer.from(parsed.header, 'hex'), key);
    key.fill(0);
  }
  get finished(): boolean { return this.#finished; }
  pull(cipher: Uint8Array, aad: Uint8Array): Buffer {
    if (this.#finished) throw new Error('Data after final record');
    if (cipher.length < ABYTES || cipher.length > RECORD_PLAINTEXT + ABYTES) throw new Error('Invalid record size');
    let result: { message: Uint8Array; tag: number } | false;
    try { result = sodium.crypto_secretstream_xchacha20poly1305_pull(this.#state, cipher, aad); } catch { result = false; }
    if (!result) throw new Error('Record authentication failed');
    if (result.tag !== TAG_MESSAGE && result.tag !== TAG_FINAL) throw new Error('Unsupported stream tag');
    this.#finished = result.tag === TAG_FINAL;
    return Buffer.from(result.message.buffer, result.message.byteOffset, result.message.byteLength);
  }
}

/** Binary stream frame: 0x01 | id[16] | sequence[8 BE] | ciphertext. */
export function encodeFrame(id: string, sequence: number, cipher: Uint8Array): Buffer {
  if (cipher.length < ABYTES || cipher.length > RECORD_PLAINTEXT + ABYTES) throw new Error('Record too large');
  const frame = Buffer.alloc(25 + cipher.length);
  frame[0] = 1;
  frame.write(id, 1, 16, 'hex');
  frame.writeBigUInt64BE(BigInt(sequence), 17);
  frame.set(cipher, 25);
  return frame;
}

export function decodeFrame(frame: Buffer): { id: string; sequence: number; cipher: Buffer } {
  if (frame.length < 25 + ABYTES || frame.length > 25 + RECORD_PLAINTEXT + ABYTES || frame[0] !== 1) throw new Error('Invalid binary frame');
  const sequence = frame.readBigUInt64BE(17);
  if (sequence > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Invalid frame sequence');
  return { id: frame.subarray(1, 17).toString('hex'), sequence: Number(sequence), cipher: frame.subarray(25) };
}
