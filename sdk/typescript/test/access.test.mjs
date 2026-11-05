// Server access password: Relay-Access header on WebSocket, group and file requests.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { WebSocketServer } from 'ws';
import { Client, Identity, Files, Groups, ACCESS_HEADER, checkAccessPassword } from '../dist/index.js';

const v = JSON.parse(readFileSync(new URL('../../../protocol/crypto-vectors.json', import.meta.url)));
const token = 'x'.repeat(64), password = 'correct-horse-1';
const bob = () => new Identity(v.app, v.group, 'bob', v.bob_secret, { alice: v.alice_public });

test('invalid access passwords are rejected at construction', async () => {
  assert.equal(ACCESS_HEADER, 'Relay-Access');
  for (const bad of ['short', 'has space1', 'a'.repeat(129), 'tab\tpassword', 'ünicode-pw', 12345678]) {
    assert.throws(() => checkAccessPassword(bad), /access password/);
    assert.throws(() => new Files('https://example.com/relay/v1/files', token, { password: bad }), /access password/);
    assert.throws(() => new Groups({ url: 'wss://example.com/relay/v1/ws', password: bad }), /access password/);
    await assert.rejects(Client.connect('wss://example.com/relay/v1/ws', token, bob(), { password: bad }), /access password/);
  }
  assert.equal(checkAccessPassword(undefined), undefined);
  assert.equal(checkAccessPassword('Abc-123!xyz'), 'Abc-123!xyz');
});

test('WebSocket upgrade sends Relay-Access only when configured', async t => {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await once(wss, 'listening');
  t.after(async () => { for (const ws of wss.clients) ws.terminate(); await new Promise(r => wss.close(r)); });
  const seen = [];
  wss.on('connection', (ws, request) => {
    seen.push(request.headers['relay-access']);
    ws.send(JSON.stringify({ type: 'welcome', version: 1, identity: { app: v.app, group: v.group, device: 'bob', public_key: v.bob_public } }));
  });
  const url = `ws://127.0.0.1:${wss.address().port}/relay/v1/ws`;
  const a = await Client.connect(url, token, bob(), { allowLocalTest: true, password }); a.close();
  const b = await Client.connect(url, token, bob(), { allowLocalTest: true }); b.close();
  assert.deepEqual(seen, [password, undefined]);
});

test('group, short-link resolve and file requests send Relay-Access', async t => {
  const seen = [];
  const http = createServer((request, response) => {
    seen.push([request.url, request.headers['relay-access'], request.headers.authorization]);
    response.writeHead(request.url.startsWith('/relay/v1/files') ? 200 : 404, { 'Content-Type': 'application/json' });
    response.end('[]');
  });
  await new Promise(r => http.listen(0, '127.0.0.1', r)); t.after(() => http.close());
  const host = `127.0.0.1:${http.address().port}`;
  const groups = new Groups({ url: `ws://${host}/relay/v1/ws`, app: 'example', group: 'g', token, password }, { allowLocalTest: true });
  await assert.rejects(groups.call('GET', '/group?after=0'), /404/);
  const link = `common-relay://${host}/i/${Buffer.alloc(16, 1).toString('base64url')}#${Buffer.alloc(32, 2).toString('base64url')}`;
  await assert.rejects(groups.resolveInvitation(link));
  const files = new Files(`http://${host}/relay/v1/files`, token, { allowLocalTest: true, password });
  assert.deepEqual(await files.inbox(), []);
  const resolved = seen.find(([u]) => u.includes('/link'));
  assert.ok(resolved, 'short link resolve request was sent');
  for (const [, access] of seen) assert.equal(access, password);
  assert.match(resolved[2], /^InvitationLink /);
  seen.length = 0;
  const foreign = new Groups({ url: 'wss://other.example/relay/v1/ws', app: 'example', group: 'g', token, password }, { allowLocalTest: true });
  await assert.rejects(foreign.resolveInvitation(link));
  assert.ok(seen[0][0].includes('/link'));
  assert.equal(seen[0][1], undefined, 'password must not go to a relay other than the configured one');
  seen.length = 0;
  await assert.rejects(new Groups({ url: `ws://${host}/relay/v1/ws`, token }, { allowLocalTest: true }).call('GET', '/group'));
  assert.equal(seen[0][1], undefined);
});
