// Loopback integration against the prebuilt relay (build/common-relay) with throwaway identities.
import { spawn, execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync, copyFileSync, openSync, readSync, closeSync } from 'node:fs';
import { createServer, connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Client, Identity, Journal, Files, prepareFile, decryptFile, safeFileName } from '../dist/index.js';

const binary = process.env.COMMON_RELAY_SERVER ?? new URL('../../../build/common-relay', import.meta.url).pathname;
const skip = existsSync(binary) ? false : `relay binary not found at ${binary}`;

async function freePort() {
  const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  await new Promise(resolve => server.close(resolve));
  return port;
}
async function relay(t, names) {
  const dir = mkdtempSync(join(tmpdir(), 'relay-ts-'));
  const keys = Object.fromEntries(names.map(name => [name, Identity.generateKeyPair()]));
  const devices = {};
  for (const name of names) {
    const out = join(dir, name + '.credential');
    execFileSync(binary, ['device-add', '--data', join(dir, 'server'), '--app', 'example', '--group', 'ts', '--device', name, '--public-key', keys[name].publicKey, '--credential-out', out], { stdio: 'ignore' });
    const trusted = Object.fromEntries(names.filter(n => n !== name).map(n => [n, keys[n].publicKey]));
    devices[name] = { identity: new Identity('example', 'ts', name, keys[name].secretKey, trusted), token: JSON.parse(readFileSync(out, 'utf8')).token, state: join(dir, name + '-state') };
  }
  const port = await freePort();
  const proc = spawn(binary, ['serve', '--data', join(dir, 'server'), '--listen', `127.0.0.1:${port}`, '--disk-reserve', '0'], { stdio: 'ignore' });
  t.after(async () => { proc.kill(); await new Promise(resolve => proc.once('exit', resolve)); rmSync(dir, { recursive: true, force: true }); });
  for (let i = 0; ; i++) {
    const ok = await new Promise(resolve => { const s = connect(port, '127.0.0.1', () => { s.end(); resolve(true); }); s.on('error', () => resolve(false)); });
    if (ok) break;
    if (i > 200) throw new Error('relay did not start');
    await new Promise(resolve => setTimeout(resolve, 25));
  }
  return { dir, url: `ws://127.0.0.1:${port}/relay/v1/ws`, files: `http://127.0.0.1:${port}/relay/v1/files`, devices };
}
const open = (env, name, journal) => Client.connect(env.url, env.devices[name].token, env.devices[name].identity, { allowLocalTest: true, journal });
async function nextOf(client, type, ms = 10000) {
  const stop = AbortSignal.timeout(ms);
  for (;;) { const event = await client.nextEvent(stop); if (event.type === type) return event; }
}
const scope = identity => JSON.stringify([identity.app, identity.group, identity.device]);

test('offline delivery: stored, retry, ack, received, lost-ACK dedupe and journal requirement', { skip }, async t => {
  const env = await relay(t, ['alice', 'bob']);
  const aliceJournal = new Journal(env.devices.alice.state), bobJournal = new Journal(env.devices.bob.state);
  t.after(() => { aliceJournal.close(); bobJournal.close(); });
  const alice = await open(env, 'alice', aliceJournal); t.after(() => alice.close());
  const id = randomBytes(16).toString('hex');
  assert.deepEqual(await alice.message('bob', Buffer.from('first'), { offline: true, id }), { type: 'stored', id });
  assert.equal((await alice.message('bob', Buffer.from('first'), { offline: true, id })).type, 'stored');
  await assert.rejects(alice.message('bob', Buffer.from('other'), { offline: true, id }), /different content/);

  const noJournal = await open(env, 'bob');
  await assert.rejects(nextOf(noJournal, 'message'), /journal/);

  let bob = await open(env, 'bob', bobJournal);
  const event = await nextOf(bob, 'message');
  assert.equal(event.offline, true); assert.equal(event.data.toString(), 'first'); assert.equal(event.id, id);
  await bob.acknowledge(event);
  assert.deepEqual(await alice.message('bob', Buffer.from('first'), { offline: true, id }), { type: 'received', id });
  assert.equal((await alice.message('bob', Buffer.from('first'), { offline: true, id })).type, 'received');

  // Lost ACK: dedupe persisted, ACK never sent. Redelivery is re-ACKed without reaching the app.
  bob.close();
  const second = randomBytes(16).toString('hex');
  assert.equal((await alice.message('bob', Buffer.from('second'), { offline: true, id: second })).type, 'stored');
  bobJournal.acknowledge(scope(env.devices.bob.identity), 'alice', second);
  bob = await open(env, 'bob', bobJournal); t.after(() => bob.close());
  let state;
  for (let i = 0; i < 100 && state !== 'received'; i++) {
    state = (await alice.message('bob', Buffer.from('second'), { offline: true, id: second })).type;
    if (state !== 'received') await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.equal(state, 'received');
  await alice.message('bob', Buffer.from('marker'));
  const marker = await nextOf(bob, 'message');
  assert.equal(marker.data.toString(), 'marker'); assert.equal(marker.offline, false);
  await bob.acknowledge(marker);
  assert.equal(alice.cleanup(), 0);
});

test('bidirectional stream: 1 MiB each way, credit flow control and FINAL', { skip }, async t => {
  const env = await relay(t, ['alice', 'bob']);
  const alice = await open(env, 'alice'), bob = await open(env, 'bob');
  t.after(() => { alice.close(); bob.close(); });
  const payload = randomBytes((1 << 20) + 12345);
  const echo = (async () => {
    const stream = await bob.acceptStream(await nextOf(bob, 'stream.open'));
    while (!stream.receivedFinal) { const data = await stream.receive(); await stream.send(data, stream.receivedFinal); }
    return stream;
  })();
  const stream = await alice.openStream('bob');
  const sending = stream.send(payload, true);
  const parts = [];
  while (!stream.receivedFinal) parts.push(await stream.receive());
  await sending;
  assert.equal(stream.sentFinal, true);
  assert.deepEqual(Buffer.concat(parts), payload);
  await assert.rejects(stream.send(Buffer.from('late')), /finished/);
  const remote = await echo;
  stream.close();
  for (let i = 0; i < 100 && !remote.closed; i++) await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(remote.closed, true);
  await assert.rejects(remote.receive(), /interrupted|closed/);
  await assert.rejects(alice.openStream('nobody'), /Untrusted/);
});

test('files: resume after 409, ranged download resume, verified publish, tamper and conflict', { skip }, async t => {
  const env = await relay(t, ['alice', 'bob']);
  const aliceFiles = new Files(env.files, env.devices.alice.token, { allowLocalTest: true });
  const bobFiles = new Files(env.url, env.devices.bob.token, { allowLocalTest: true });
  assert.throws(() => new Files(env.files, env.devices.bob.token), /HTTPS/);
  assert.throws(() => new Files('https://example.com/other', env.devices.bob.token), /HTTPS/);
  const source = join(env.dir, 'source.bin'), staged = join(env.dir, 'alice.enc');
  const plain = randomBytes(2_500_000);
  writeFileSync(source, plain);
  const info = await prepareFile(env.devices.alice.identity, 'bob', source, staged, { name: '../evil/name.bin' });
  await assert.rejects(prepareFile(env.devices.alice.identity, 'bob', source, staged), /EEXIST/);
  assert.equal(info.size, readFileSync(staged).length);
  // A previous attempt created the upload and sent the first chunk.
  const auth = { Authorization: `Bearer ${env.devices.alice.token}` };
  assert.equal((await fetch(env.files, { method: 'POST', headers: { ...auth, 'Content-Type': 'application/json' }, body: JSON.stringify(info) })).status, 201);
  const first = readFileSync(staged).subarray(0, 1 << 20);
  assert.equal((await fetch(`${env.files}/${info.id}/data`, { method: 'PUT', headers: { ...auth, 'Upload-Offset': '0' }, body: first })).status, 200);
  await assert.rejects(aliceFiles.upload({ ...info, sha256: '00'.repeat(32) }, staged), /conflict/);
  const committed = await aliceFiles.upload(info, staged);
  assert.equal(committed.state, 'ready');
  const inbox = await bobFiles.inbox();
  assert.equal(inbox.length, 1); assert.equal(inbox[0].id, info.id);
  const received = join(env.dir, 'bob.enc');
  const fd = openSync(staged, 'r'), head = Buffer.alloc(1500000); readSync(fd, head, 0, head.length, 0); closeSync(fd);
  writeFileSync(received, head);
  await bobFiles.download(inbox[0], received);
  assert.equal(createHash('sha256').update(readFileSync(received)).digest('hex'), info.sha256);
  const destination = join(env.dir, 'output.bin');
  const metadata = await decryptFile(env.devices.bob.identity, 'alice', inbox[0], received, destination);
  assert.deepEqual(readFileSync(destination), plain);
  assert.equal(safeFileName(metadata.name), '.._evil_name.bin'.replace(/^\.+/, ''));
  await assert.rejects(decryptFile(env.devices.bob.identity, 'alice', inbox[0], received, destination), /EEXIST/);
  const damaged = join(env.dir, 'damaged.enc');
  copyFileSync(received, damaged);
  const bytes = readFileSync(damaged); bytes[100] ^= 1; writeFileSync(damaged, bytes);
  await assert.rejects(decryptFile(env.devices.bob.identity, 'alice', inbox[0], damaged, join(env.dir, 'never.bin')), /digest/);
  assert.equal(existsSync(join(env.dir, 'never.bin')), false);
  // Integrity of the digest alone is not enough: a record set without FINAL is never published.
  const truncated = join(env.dir, 'truncated.enc');
  const all = readFileSync(received), lastLength = 4 + 17;
  writeFileSync(truncated, all.subarray(0, all.length - lastLength));
  const forged = { ...inbox[0], size: all.length - lastLength, sha256: createHash('sha256').update(all.subarray(0, all.length - lastLength)).digest('hex') };
  await assert.rejects(decryptFile(env.devices.bob.identity, 'alice', forged, truncated, join(env.dir, 'never.bin')), /final/);
  assert.equal(existsSync(join(env.dir, 'never.bin')), false);
  await bobFiles.acknowledge(info.id);
  await assert.rejects(bobFiles.status(info.id), /404/);
  assert.deepEqual(await bobFiles.inbox(), []);
});

test('files reject redirects instead of forwarding the bearer token', { skip: false }, async t => {
  const { createServer: http } = await import('node:http');
  let leaked = false;
  const target = http((request, response) => { leaked = Boolean(request.headers.authorization); response.end('[]'); });
  await new Promise(resolve => target.listen(0, '127.0.0.1', resolve)); t.after(() => target.close());
  const source = http((request, response) => { response.writeHead(307, { Location: `http://127.0.0.1:${target.address().port}/relay/v1/files` }); response.end(); });
  await new Promise(resolve => source.listen(0, '127.0.0.1', resolve)); t.after(() => source.close());
  const files = new Files(`http://127.0.0.1:${source.address().port}/relay/v1/files`, 'x'.repeat(64), { allowLocalTest: true });
  await assert.rejects(files.inbox());
  assert.equal(leaked, false);
  assert.equal(safeFileName('CON.txt'), '_CON.txt');
  assert.equal(safeFileName('a/b\\c\u0000d'), 'a_b_c_d');
  assert.equal(safeFileName('...'), 'file');
});
