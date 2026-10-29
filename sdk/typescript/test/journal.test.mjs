import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Journal } from '../dist/index.js';

function directory(t) {
  const path = mkdtempSync(join(tmpdir(), 'relay-journal-'));
  t.after(() => rmSync(path, { recursive: true, force: true }));
  return path;
}
const records = path => readdirSync(path).filter(name => name.endsWith('.json'));

test('restart preserves ciphertext and expiry; conflicts rejected; cleanup keeps tombstones', t => {
  const path = directory(t);
  let now = 1000000;
  let journal = new Journal(path, { clock: () => now });
  const data = Buffer.from([1, 2, 3]);
  const first = journal.prepare('a', 'id', 'b', data, 60, expires => `cipher-${expires}`);
  assert.equal(first.expires, now + 60);
  journal.close();
  now += 30; journal = new Journal(path, { clock: () => now });
  const retry = journal.prepare('a', 'id', 'b', data, 86400, () => { throw new Error('re-encrypted'); });
  assert.equal(retry.body, first.body); assert.equal(retry.expires, first.expires);
  assert.throws(() => journal.prepare('a', 'id', 'b', Buffer.alloc(0), 60, () => 'bad'), /different content/);
  assert.throws(() => journal.prepare('a', 'id', 'c', data, 60, () => 'bad'), /different content/);
  assert.throws(() => journal.prepare('a', 'x', 'b', data, 0, () => 'bad'), /TTL/);
  assert.throws(() => journal.prepare('a', 'x', 'b', data, 86401, () => 'bad'), /TTL/);
  journal.acknowledge('a', 'b', 'in');
  assert.equal(journal.contains('a', 'b', 'in'), true);
  assert.equal(journal.contains('other', 'b', 'in'), false);
  assert.equal(journal.contains('a', 'c', 'in'), false);
  now += 30; assert.equal(journal.cleanup(), 1);
  assert.throws(() => journal.prepare('a', 'id', 'b', data, 60, () => 'bad'), /expired/);
  for (const name of records(path)) assert.equal(readFileSync(join(path, name), 'utf8').includes('cipher'), false);
  // Repeated acknowledgment does not extend dedupe retention.
  now += 3600; journal.acknowledge('a', 'b', 'in');
  now += 7 * 86400 - 3600; assert.equal(journal.contains('a', 'b', 'in'), false);
  journal.cleanup(); assert.deepEqual(records(path), []);
  journal.prepare('a', 'done', 'b', data, 60, () => 'cipher');
  journal.complete('a', 'done');
  assert.equal(journal.prepare('a', 'done', 'b', data, 60, () => 'bad').status, 'received');
  assert.equal(readFileSync(join(path, records(path)[0]), 'utf8').includes('cipher'), false);
  journal.close();
  assert.throws(() => journal.contains('a', 'b', 'x'), /closed/);
});

test('one owner per directory; stale locks from dead processes are reclaimed', t => {
  const path = directory(t);
  const journal = new Journal(path);
  assert.throws(() => new Journal(path), /owner/);
  journal.close();
  new Journal(path).close();
  writeFileSync(join(path, 'owner.lock'), String(process.ppid));
  assert.throws(() => new Journal(path), /owned by process/);
  writeFileSync(join(path, 'owner.lock'), '999999999');
  new Journal(path).close();
});

test('cleanup is bounded to 256 changes per round and reports corrupt records', t => {
  const path = directory(t);
  let now = 5000;
  const journal = new Journal(path, { clock: () => now });
  for (let i = 0; i < 300; i++) journal.acknowledge('s', 'peer', String(i));
  now += 7 * 86400;
  assert.equal(journal.cleanup(), 256);
  assert.equal(records(path).length, 44);
  assert.equal(journal.cleanup(), 44);
  writeFileSync(join(path, 'a'.repeat(64) + '.json'), '{"purge":"x"}');
  assert.throws(() => journal.cleanup(), /Corrupt/);
  journal.close();
});
