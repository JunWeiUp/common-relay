import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { once } from 'node:events';
import { WebSocketServer } from 'ws';
import { Client, Identity, Journal, EncryptStream, recordAAD, encodeFrame } from '../dist/index.js';

const v = JSON.parse(readFileSync(new URL('../../../protocol/crypto-vectors.json', import.meta.url)));
const alice = () => new Identity(v.app, v.group, 'alice', v.alice_secret, { bob: v.bob_public });
const bob = () => new Identity(v.app, v.group, 'bob', v.bob_secret, { alice: v.alice_public });
const token = 'x'.repeat(64);
test('shared vector, round trip, peer pinning and authenticated context', () => {
  const a = alice(), b = bob();
  assert.equal(b.publicKey, v.bob_public);
  assert.equal(b.openMessage('alice', v.id, v.message).toString(), 'hello');
  assert.equal(b.openMessage('alice', v.id, a.sealMessage('bob', v.id, Buffer.from('你好'))).toString(), '你好');
  assert.throws(() => b.openMessage('alice', '02'.repeat(16), v.message), /context/);
  assert.throws(() => b.openMessage('mallory', v.id, v.message), /Untrusted/);
  assert.throws(() => b.openMessage('alice', v.id, v.message.slice(0, -4) + 'AAAA'));
  assert.throws(() => b.openMessage('alice', v.id, v.offline_message), /Expired/);
  assert.throws(() => a.sealMessage('bob', v.id, new Uint8Array(200000)), /large/);
  assert.throws(() => new Identity(v.app,v.group,'alice',v.alice_secret,{bob:'00'.repeat(32)}).sealMessage('bob',v.id,Buffer.from('x')), /peer key/);
  const pair = Identity.generateKeyPair();
  assert.equal(new Identity('example','test','new',pair.secretKey,{}).publicKey, pair.publicKey);
});

async function until(check) { for (let i = 0; i < 200 && !check(); i++) await new Promise(resolve => setTimeout(resolve, 10)); }
async function server(t, handler, own = {}) {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await once(wss, 'listening');
  t.after(async () => { for (const ws of wss.clients) ws.terminate(); await new Promise(resolve => wss.close(resolve)); });
  wss.on('connection', (ws, request) => {
    assert.equal(request.headers.authorization, `Bearer ${token}`);
    ws.send(JSON.stringify({ type: 'welcome', version: 1, identity: { app:v.app,group:v.group,device:'bob',public_key:v.bob_public,...own } }));
    handler(ws);
  });
  return `ws://127.0.0.1:${wss.address().port}/relay/v1/ws`;
}

test('online send, encrypted receive, peer discovery and cancellation', async t => {
  const url = await server(t, ws => ws.on('message', raw => {
    const e=JSON.parse(raw);
    if (e.type==='peers') ws.send(JSON.stringify({type:'peers',id:e.id,devices:[{app:v.app,group:v.group,device:'alice',public_key:v.alice_public}]}));
    else {
      assert.equal(e.offline,false);
      assert.equal(alice().openMessage('bob',e.id,e.body).toString(),'hello');
      ws.send(JSON.stringify({type:'forwarded',id:e.id}));
      ws.send(JSON.stringify({type:'message',id:v.id,from:'alice',body:v.message}));
    }
  }));
  const c=await Client.connect(url,token,bob(),{allowLocalTest:true});t.after(()=>c.close());
  assert.equal((await c.peers())[0].device,'alice');
  assert.equal((await c.message('alice',Buffer.from('hello'))).type,'forwarded');
  assert.equal((await c.nextEvent()).data.toString(),'hello');
  const stop=new AbortController(), pending=c.nextEvent(stop.signal);stop.abort();
  await assert.rejects(pending,/cancelled/);
  const blocked=c.nextEvent();c.close();await assert.rejects(blocked,/closed/);
});

test('reject insecure endpoints, mismatched welcome and redirect without following', async t => {
  await assert.rejects(Client.connect('ws://127.0.0.1:1/relay/v1/ws',token,bob()), /WSS/);
  await assert.rejects(Client.connect('wss://example.com/relay/v1/ws?token=x',token,bob()), /WSS/);
  const url=await server(t,()=>{}, {group:'other'});
  await assert.rejects(Client.connect(url,token,bob(),{allowLocalTest:true}),/mismatch/);
});

test('request timeout cleans pending state; closing rejects waits', async t => {
  const url=await server(t,()=>{});
  const c=await Client.connect(url,token,bob(),{allowLocalTest:true,timeoutMs:100});t.after(()=>c.close());
  await assert.rejects(c.peers(),/timed out/);
  const pending=c.peers();c.close();await assert.rejects(pending,/closed/);
});

test('offline message is rejected without a journal; stream requests are offered and can be rejected', async t => {
  let ws;const url=await server(t, socket=>{ws=socket;});
  const c=await Client.connect(url,token,bob(),{allowLocalTest:true});t.after(()=>c.close());
  await assert.rejects(c.message('alice',Buffer.from('x'),{offline:true}),/journal/);
  const body=alice().seal('bob','stream.open',v.id,{key:'00'.repeat(32),header:'00'.repeat(24)});
  ws.send(JSON.stringify({type:'stream.open',id:v.id,from:'alice',body}));
  const request=await c.nextEvent();assert.equal(request.type,'stream.open');assert.equal(request.from,'alice');
  const reply=once(ws,'message');c.rejectStream(request);
  assert.deepEqual(JSON.parse((await reply)[0]),{type:'stream.close',id:v.id});
  const pending=c.nextEvent();ws.send(JSON.stringify({type:'message',id:v.id,from:'alice',body:v.message,offline:true}));
  await assert.rejects(pending,/Offline/);
});

test('redirect is not followed and authorization stays at the original endpoint', async t => {
  const {createServer}=await import('node:http');let redirected=false;
  const target=createServer();target.on('upgrade',(_,socket)=>{redirected=true;socket.destroy();});
  target.listen(0,'127.0.0.1');await once(target,'listening');t.after(()=>target.close());
  const source=createServer();source.on('upgrade',(_,socket)=>socket.end(`HTTP/1.1 302 Found\r\nLocation: ws://127.0.0.1:${target.address().port}/relay/v1/ws\r\nContent-Length: 0\r\n\r\n`));
  source.listen(0,'127.0.0.1');await once(source,'listening');t.after(()=>source.close());
  await assert.rejects(Client.connect(`ws://127.0.0.1:${source.address().port}/relay/v1/ws`,token,bob(),{allowLocalTest:true}));
  assert.equal(redirected,false);
});

test('expired or already acknowledged offline redelivery is re-ACKed, not delivered', async t => {
  const { mkdtempSync, rmSync } = await import('node:fs'); const { tmpdir } = await import('node:os'); const { join } = await import('node:path');
  const dir = mkdtempSync(join(tmpdir(), 'relay-ts-')); t.after(() => rmSync(dir, { recursive: true, force: true }));
  const journal = new Journal(dir); t.after(() => journal.close());
  let ws; const url = await server(t, socket => { ws = socket; });
  const c = await Client.connect(url, token, bob(), { allowLocalTest: true, journal }); t.after(() => c.close());
  const acks = [];
  ws.on('message', raw => { const e = JSON.parse(raw); if (e.type === 'ack') { acks.push(e.id); ws.send(JSON.stringify({ type: 'acked', id: e.id })); } });
  ws.send(JSON.stringify({ type: 'message', id: v.id, from: 'alice', body: v.offline_message, offline: true }));
  const fresh = '03'.repeat(16);
  ws.send(JSON.stringify({ type: 'message', id: fresh, from: 'alice', body: alice().sealMessage('bob', fresh, Buffer.from('new'), Math.floor(Date.now() / 1000) + 60), offline: true }));
  const event = await c.nextEvent();
  assert.equal(event.id, fresh); assert.equal(event.offline, true);
  await until(() => acks.length === 1); assert.deepEqual(acks, [v.id]);
  await c.acknowledge(event);
  ws.send(JSON.stringify({ type: 'message', id: fresh, from: 'alice', body: alice().sealMessage('bob', fresh, Buffer.from('new'), Math.floor(Date.now() / 1000) + 60), offline: true }));
  ws.send(JSON.stringify({ type: 'message', id: v.id, from: 'alice', body: v.message }));
  assert.equal((await c.nextEvent()).data.toString(), 'hello');
  await until(() => acks.length === 3); assert.deepEqual(acks, [v.id, fresh, fresh]);
});

test('stream records out of order or duplicated terminate the stream', async t => {
  let ws; const url = await server(t, socket => { ws = socket; });
  const c = await Client.connect(url, token, bob(), { allowLocalTest: true }); t.after(() => c.close());
  const tx = new EncryptStream();
  const seen = [];
  ws.on('message', (raw, binary) => {
    if (binary) return;
    const e = JSON.parse(raw); seen.push(e.type);
    if (e.type === 'stream.open') ws.send(JSON.stringify({ type: 'stream.accept', id: e.id, from: 'alice', body: alice().seal('bob', 'stream.accept', e.id, tx.descriptor) }));
  });
  const stream = await c.openStream('alice');
  const aad = seq => recordAAD(v.app, v.group, 'alice', 'bob', 'stream', stream.id, seq);
  const zero = tx.push(Buffer.from('zero'), aad(0)), one = tx.push(Buffer.from('one'), aad(1));
  ws.send(encodeFrame(stream.id, 0, zero)); ws.send(encodeFrame(stream.id, 0, zero));
  assert.equal((await stream.receive()).toString(), 'zero');
  await assert.rejects(stream.receive(), /sequence/);
  assert.equal(stream.closed, true);
  await new Promise(resolve => setTimeout(resolve, 50));
  assert.deepEqual(seen, ['stream.open', 'stream.credit', 'stream.close']);
  void one;
});
