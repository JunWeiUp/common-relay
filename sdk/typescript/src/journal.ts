import { createHash, randomBytes } from 'node:crypto';
import { closeSync, fsyncSync, mkdirSync, openSync, readFileSync, readdirSync, renameSync, rmSync, unlinkSync, writeSync, lstatSync } from 'node:fs';
import { join, resolve } from 'node:path';

/** Terminal states and receive dedupe records are retained for 7 days. */
export const RETENTION_SECONDS = 7 * 86400;
/** Maximum file changes per cleanup round. */
export const CLEANUP_BATCH = 256;
const RECORD_NAME = /^[a-f0-9]{64}\.json$/;
const TEMPORARY_NAME = /^[a-f0-9]{64}\.json\.[a-f0-9]{16}\.tmp$/;
const LOCK_NAME = 'owner.lock';
const owned = new Set<string>();
let exitHook = false;

export type OutboxStatus = 'pending' | 'received' | 'expired';
export interface OutboxRecord { recipient: string; digest: string; body?: string; expires: number; purge: number; status: OutboxStatus }
interface InboxRecord { purge: number }
export interface JournalOptions { clock?: () => number }

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch (error) { return (error as NodeJS.ErrnoException).code === 'EPERM'; }
}
function integer(value: unknown): value is number { return Number.isSafeInteger(value); }

/**
 * Durable offline delivery state: one record file per outgoing message or received dedupe entry,
 * replaced atomically (temporary file + fsync + rename). Records never contain tokens, private keys
 * or plaintext; outgoing records keep only recipient, content digest, original ciphertext and expiry.
 *
 * One owner per directory: an `owner.lock` file (PID) plus an in-process registry reject a second
 * instance. Use an application-private directory and call close() to release it.
 */
export class Journal {
  readonly directory: string;
  readonly #clock: () => number;
  #closed = false;

  constructor(directory: string, options: JournalOptions = {}) {
    this.directory = resolve(directory);
    this.#clock = options.clock ?? (() => Math.floor(Date.now() / 1000));
    mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    if (!lstatSync(this.directory).isDirectory()) throw new Error('Journal path is not a directory');
    if (owned.has(this.directory)) throw new Error('Journal directory already has an owner');
    this.#lock();
    owned.add(this.directory);
    if (!exitHook) {
      exitHook = true;
      process.once('exit', () => { for (const directory of owned) { try { unlinkSync(join(directory, LOCK_NAME)); } catch { /* best effort */ } } });
    }
    try { this.cleanup(); } catch (error) { this.close(); throw error; }
  }

  #lock(): void {
    const path = join(this.directory, LOCK_NAME);
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const fd = openSync(path, 'wx', 0o600);
        try { writeSync(fd, String(process.pid)); fsyncSync(fd); } finally { closeSync(fd); }
        return;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      }
      const pid = Number(readFileSync(path, 'utf8'));
      // A lock held by this process without a registry entry was left by an unclosed instance that
      // can no longer write; any other live process keeps ownership.
      if (Number.isSafeInteger(pid) && pid > 0 && pid !== process.pid && alive(pid)) throw new Error(`Journal directory is owned by process ${pid}`);
      rmSync(path, { force: true });
    }
    throw new Error('Journal directory lock contention');
  }

  /** Releases directory ownership. Further use throws. */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    owned.delete(this.directory);
    rmSync(join(this.directory, LOCK_NAME), { force: true });
  }

  #now(): number {
    if (this.#closed) throw new Error('Journal closed');
    const now = this.#clock();
    if (!integer(now)) throw new Error('Invalid journal clock');
    return now;
  }
  #path(scope: string, kind: 'in' | 'out', sender: string, id: string): string {
    if (this.#closed) throw new Error('Journal closed');
    return join(this.directory, createHash('sha256').update(JSON.stringify([scope, kind, sender, id])).digest('hex') + '.json');
  }
  #read(path: string): Record<string, unknown> | undefined {
    let text: string;
    try { text = readFileSync(path, 'utf8'); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw error;
    }
    const value = JSON.parse(text) as unknown;
    if (!value || typeof value !== 'object' || Array.isArray(value) || !integer((value as Record<string, unknown>).purge)) throw new Error('Corrupt journal record');
    return value as Record<string, unknown>;
  }
  #write(path: string, record: object): void {
    const temporary = `${path}.${randomBytes(8).toString('hex')}.tmp`;
    try {
      const fd = openSync(temporary, 'wx', 0o600);
      try { writeSync(fd, JSON.stringify(record)); fsyncSync(fd); } finally { closeSync(fd); }
      renameSync(temporary, path);
    } finally { rmSync(temporary, { force: true }); }
    try { const fd = openSync(this.directory, 'r'); try { fsyncSync(fd); } finally { closeSync(fd); } } catch { /* directory fsync unsupported */ }
  }
  #outbox(path: string): OutboxRecord | undefined {
    const row = this.#read(path);
    if (!row) return undefined;
    if (typeof row.recipient !== 'string' || typeof row.digest !== 'string' || !integer(row.expires)
      || !['pending', 'received', 'expired'].includes(row.status as string) || (row.status === 'pending' && typeof row.body !== 'string')) throw new Error('Corrupt journal record');
    return row as unknown as OutboxRecord;
  }

  /**
   * Persists recipient, SHA-256 content digest, ciphertext and the fixed absolute expiry before sending.
   * A retry with the same ID returns the original ciphertext/expiry; different content or recipient is rejected.
   */
  prepare(scope: string, id: string, recipient: string, data: Uint8Array, ttl: number, seal: (expires: number) => string): OutboxRecord {
    if (!integer(ttl) || ttl < 1 || ttl > 86400) throw new Error('Invalid TTL');
    const path = this.#path(scope, 'out', '', id), now = this.#now();
    const digest = createHash('sha256').update(data).digest('hex');
    const old = this.#outbox(path);
    if (old) {
      if (old.recipient !== recipient || old.digest !== digest) throw new Error('Message ID reused with different content');
      if (old.status === 'received') return old;
      if (old.status !== 'pending' || old.expires <= now) throw new Error('Message expired');
      return old;
    }
    const expires = now + ttl;
    const record: OutboxRecord = { recipient, digest, body: seal(expires), expires, purge: expires + RETENTION_SECONDS, status: 'pending' };
    this.#write(path, record);
    return record;
  }
  /** The peer acknowledged: drop the ciphertext and keep the terminal state for 7 days. */
  complete(scope: string, id: string): void {
    const path = this.#path(scope, 'out', '', id), row = this.#outbox(path);
    if (!row) return;
    this.#write(path, { recipient: row.recipient, digest: row.digest, expires: row.expires, purge: this.#now() + RETENTION_SECONDS, status: 'received' });
  }
  contains(scope: string, sender: string, id: string): boolean {
    const row = this.#read(this.#path(scope, 'in', sender, id)) as InboxRecord | undefined;
    return row !== undefined && row.purge > this.#now();
  }
  /** Persists the dedupe record; a repeated acknowledgment does not extend retention. */
  acknowledge(scope: string, sender: string, id: string): void {
    if (!this.contains(scope, sender, id)) this.#write(this.#path(scope, 'in', sender, id), { purge: this.#now() + RETENTION_SECONDS });
  }
  /** Expires pending ciphertext and purges old records, at most `batch` file changes per call. */
  cleanup(batch = CLEANUP_BATCH): number {
    const now = this.#now();
    let changed = 0;
    for (const name of readdirSync(this.directory)) {
      if (changed >= batch) break;
      const path = join(this.directory, name);
      if (TEMPORARY_NAME.test(name)) { rmSync(path, { force: true }); changed++; continue; }
      if (!RECORD_NAME.test(name)) continue;
      const row = this.#read(path);
      if (!row) continue;
      if ((row.purge as number) <= now) { unlinkSync(path); changed++; }
      else if (row.status === 'pending' && integer(row.expires) && row.expires <= now) {
        this.#write(path, { recipient: row.recipient, digest: row.digest, expires: row.expires, purge: row.purge, status: 'expired' });
        changed++;
      }
    }
    return changed;
  }
}

