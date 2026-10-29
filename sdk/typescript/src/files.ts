import { createHash, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { open, link, unlink, stat } from 'node:fs/promises';
import { basename } from 'node:path';
import type { Identity } from './index.js';
import { DecryptStream, EncryptStream, RECORD_PLAINTEXT, parseDescriptor, recordAAD } from './stream-crypto.js';

/** Upload descriptor sent to `POST /relay/v1/files`. size and sha256 cover the complete ciphertext file. */
export interface FileInfo { id: string; to: string; size: number; metadata: string; sha256: string; expires?: number }
export interface FileStatus extends FileInfo { offset: number; [key: string]: unknown }
export interface FilesOptions { allowLocalTest?: boolean; timeoutMs?: number }

const CHUNK = 1 << 20;
const objectID = /^[a-f0-9]{32}$/;
const MAX_RECORD = RECORD_PLAINTEXT + 17;

function aad(identity: Identity, sender: string, recipient: string, id: string, sequence: number): Buffer {
  return recordAAD(identity.app, identity.group, sender, recipient, 'file', id, sequence);
}
async function sha256File(path: string): Promise<{ digest: string; size: number }> {
  const hash = createHash('sha256');
  let size = 0;
  for await (const chunk of createReadStream(path)) { hash.update(chunk as Buffer); size += (chunk as Buffer).length; }
  return { digest: hash.digest('hex'), size };
}
function checkInfo(value: unknown): FileInfo {
  const info = value as Record<string, unknown> | null;
  if (!info || typeof info !== 'object' || typeof info.id !== 'string' || !objectID.test(info.id) || typeof info.to !== 'string'
    || !Number.isSafeInteger(info.size) || (info.size as number) < 0 || typeof info.metadata !== 'string'
    || typeof info.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(info.sha256)) throw new Error('Invalid file descriptor');
  return info as unknown as FileInfo;
}

/**
 * Turns remote metadata into a single safe path component. Never join an unsanitized remote name
 * to a directory; the application still chooses the directory and must not overwrite existing files.
 */
export function safeFileName(name: unknown, fallback = 'file'): string {
  let text = typeof name === 'string' ? name.normalize('NFC') : '';
  text = text.replace(/[\u0000-\u001f\u007f-\u009f/\\:*?"<>|‪-‮⁦-⁩]/g, '_').replace(/^[.\s]+|[.\s]+$/g, '');
  if (/^(con|prn|aux|nul|com\d|lpt\d)(\..*)?$/i.test(text)) text = '_' + text;
  while (Buffer.byteLength(text) > 200) text = text.slice(0, -1);
  return text || fallback;
}

/**
 * Encrypts `source` into a new staging file (must not exist) as `length[4 BE] | secretstream record`
 * records ending with an empty FINAL record. Keep the staging file to resume uploads.
 */
export async function prepareFile(identity: Identity, recipient: string, source: string, staged: string,
  metadata: Record<string, unknown> = { name: basename(source) }): Promise<FileInfo> {
  const id = randomBytes(16).toString('hex');
  const crypt = new EncryptStream();
  const input = await open(source, 'r');
  const output = await open(staged, 'wx', 0o600).catch(async error => { await input.close(); throw error; });
  const digest = createHash('sha256');
  let size = 0;
  try {
    const buffer = Buffer.alloc(RECORD_PLAINTEXT);
    for (let sequence = 0; ; sequence++) {
      let filled = 0;
      while (filled < buffer.length) {
        const { bytesRead } = await input.read(buffer, filled, buffer.length - filled, null);
        if (bytesRead === 0) break;
        filled += bytesRead;
      }
      const data = buffer.subarray(0, filled);
      const cipher = crypt.push(data, aad(identity, identity.device, recipient, id, sequence), filled === 0);
      const record = Buffer.alloc(4 + cipher.length);
      record.writeUInt32BE(cipher.length, 0);
      record.set(cipher, 4);
      await output.write(record);
      digest.update(record);
      size += record.length;
      if (filled === 0) break;
    }
    await output.sync();
  } catch (error) {
    await output.close().catch(() => undefined);
    await unlink(staged).catch(() => undefined);
    throw error;
  } finally {
    await input.close();
    await output.close().catch(() => undefined);
  }
  const envelope = identity.seal(recipient, 'file', id, { ...crypt.descriptor, metadata });
  return { id, to: recipient, size, metadata: envelope, sha256: digest.digest('hex') };
}

/**
 * Verifies the ciphertext digest, authenticates every record and the FINAL tag into a private
 * temporary file, then publishes it to `destination` without replacing an existing file.
 * Returns the sender's authenticated metadata (use safeFileName for any remote name).
 */
export async function decryptFile(identity: Identity, sender: string, value: FileInfo, staged: string, destination: string): Promise<Record<string, unknown>> {
  const info = checkInfo(value);
  const { digest, size } = await sha256File(staged);
  if (size !== info.size || digest !== info.sha256) throw new Error('Ciphertext digest mismatch');
  const descriptor = identity.open(sender, 'file', info.id, info.metadata);
  const metadata = descriptor.metadata;
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) throw new Error('Invalid file metadata');
  const crypt = new DecryptStream(parseDescriptor(descriptor));
  const temporary = `${destination}.${randomBytes(16).toString('hex')}.partial`;
  const input = await open(staged, 'r');
  const output = await open(temporary, 'wx', 0o600).catch(async error => { await input.close(); throw error; });
  try {
    const prefix = Buffer.alloc(4), record = Buffer.alloc(MAX_RECORD);
    let position = 0;
    for (let sequence = 0; position < size; sequence++) {
      if ((await input.read(prefix, 0, 4, position)).bytesRead !== 4) throw new Error('Truncated record');
      const length = prefix.readUInt32BE(0);
      if (length < 17 || length > MAX_RECORD) throw new Error('Invalid record size');
      if ((await input.read(record, 0, length, position + 4)).bytesRead !== length) throw new Error('Truncated ciphertext');
      await output.write(crypt.pull(record.subarray(0, length), aad(identity, sender, identity.device, info.id, sequence)));
      position += 4 + length;
    }
    if (!crypt.finished) throw new Error('Missing authenticated final record');
    await output.sync();
    await output.close();
    // link() fails if the destination exists: never silently replace an application file.
    await link(temporary, destination);
    return metadata as Record<string, unknown>;
  } finally {
    await input.close();
    await output.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
  }
}

/** `/relay/v1/files` HTTP client. Redirects are rejected so the bearer token never leaves the origin. */
export class Files {
  readonly base: string;
  readonly #token: string;
  readonly #timeoutMs: number;
  /** `url` is `https://host/relay/v1/files` or the relay `wss://host/relay/v1/ws` endpoint. */
  constructor(url: string, token: string, options: FilesOptions = {}) {
    const endpoint = new URL(url);
    if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new Error('An HTTPS files endpoint is required');
    if (endpoint.protocol === 'wss:' || endpoint.protocol === 'ws:') {
      if (endpoint.pathname !== '/relay/v1/ws') throw new Error('An HTTPS files endpoint is required');
      endpoint.protocol = endpoint.protocol === 'wss:' ? 'https:' : 'http:';
      endpoint.pathname = '/relay/v1/files';
    }
    const local = options.allowLocalTest === true && endpoint.protocol === 'http:' && endpoint.hostname === '127.0.0.1';
    if ((endpoint.protocol !== 'https:' && !local) || endpoint.pathname.replace(/\/$/, '') !== '/relay/v1/files') throw new Error('An HTTPS files endpoint is required');
    if (!/^[A-Za-z0-9_-]{32,256}$/.test(token)) throw new Error('Invalid device credential');
    const timeout = options.timeoutMs ?? 60000;
    if (!Number.isSafeInteger(timeout) || timeout < 1 || timeout > 600000) throw new Error('Invalid timeout');
    this.base = endpoint.origin + '/relay/v1/files';
    this.#token = token;
    this.#timeoutMs = timeout;
  }

  async #request(method: string, path: string, body?: Buffer | string, headers: Record<string, string> = {}): Promise<Response> {
    if (path && !/^\/[a-f0-9]{32}(\/data|\/commit)?$/.test(path)) throw new Error('Invalid file path');
    return fetch(this.base + path, {
      method, body: body as BodyInit | undefined, redirect: 'error', signal: AbortSignal.timeout(this.#timeoutMs),
      headers: { Authorization: `Bearer ${this.#token}`, ...headers },
    });
  }
  async #json(response: Response, expected: number[], what: string): Promise<unknown> {
    if (!expected.includes(response.status)) { await response.body?.cancel(); throw new Error(`${what} failed (${response.status})`); }
    const raw = Buffer.from(await response.arrayBuffer());
    if (raw.length > 4 << 20) throw new Error('Response too large');
    return JSON.parse(raw.toString('utf8'));
  }

  /** Creates or resumes (after 409, with a strict descriptor comparison) an upload, then commits it. */
  async upload(value: FileInfo, staged: string): Promise<Record<string, unknown>> {
    const info = checkInfo(value);
    const { size } = await stat(staged);
    if (size !== info.size) throw new Error('Staging file size mismatch');
    let response = await this.#request('POST', '', JSON.stringify(info), { 'Content-Type': 'application/json' });
    if (response.status === 409) { await response.body?.cancel(); response = await this.#request('GET', '/' + info.id); }
    const status = await this.#json(response, [200, 201], 'File admission') as Record<string, unknown>;
    for (const field of ['id', 'to', 'size', 'metadata', 'sha256'] as const) if (status[field] !== info[field]) throw new Error('Upload ID conflict');
    let offset = status.offset;
    if (!Number.isSafeInteger(offset) || (offset as number) < 0 || (offset as number) > info.size) throw new Error('Invalid upload offset');
    const input = await open(staged, 'r');
    try {
      const buffer = Buffer.alloc(CHUNK);
      while ((offset as number) < info.size) {
        const { bytesRead } = await input.read(buffer, 0, Math.min(CHUNK, info.size - (offset as number)), offset as number);
        if (bytesRead === 0) throw new Error('Staging file truncated');
        const result = await this.#json(await this.#request('PUT', `/${info.id}/data`, buffer.subarray(0, bytesRead),
          { 'Upload-Offset': String(offset), 'Content-Type': 'application/octet-stream' }), [200], 'Upload') as Record<string, unknown>;
        if (result.offset !== (offset as number) + bytesRead) throw new Error('Invalid upload progress');
        offset = result.offset;
      }
    } finally { await input.close(); }
    return await this.#json(await this.#request('POST', `/${info.id}/commit`), [200], 'Commit') as Record<string, unknown>;
  }
  /** Ready, unexpired files addressed to this device. */
  async inbox(): Promise<FileStatus[]> {
    const list = await this.#json(await this.#request('GET', ''), [200], 'Inbox');
    if (!Array.isArray(list)) throw new Error('Invalid file inbox');
    return list.map(item => checkInfo(item) as FileStatus);
  }
  async status(id: string): Promise<FileStatus> {
    return checkInfo(await this.#json(await this.#request('GET', '/' + id), [200], 'Status')) as FileStatus;
  }
  /** Appends missing ciphertext to `staged` using ranged requests; resumes from the staged length. */
  async download(value: FileInfo, staged: string): Promise<void> {
    const info = checkInfo(value);
    const output = await open(staged, 'a', 0o600);
    try {
      let offset = (await output.stat()).size;
      if (offset > info.size) throw new Error('Staged file exceeds declared size');
      while (offset < info.size) {
        const end = Math.min(info.size, offset + CHUNK) - 1;
        const response = await this.#request('GET', `/${info.id}/data`, undefined, { Range: `bytes=${offset}-${end}` });
        if (response.status !== 206) { await response.body?.cancel(); throw new Error(`Invalid range download (${response.status})`); }
        const chunk = Buffer.from(await response.arrayBuffer());
        if (chunk.length !== end - offset + 1) throw new Error('Invalid range download length');
        await output.write(chunk);
        offset += chunk.length;
      }
      await output.sync();
    } finally { await output.close(); }
  }
  /** Sender cancels or recipient confirms; the relay deletes the object. */
  async delete(id: string): Promise<void> {
    const response = await this.#request('DELETE', '/' + id);
    await response.body?.cancel();
    if (response.status !== 204) throw new Error(`Delete failed (${response.status})`);
  }
  acknowledge(id: string): Promise<void> { return this.delete(id); }
}
