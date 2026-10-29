import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Identity, EncryptStream, DecryptStream, recordAAD, encodeFrame, decodeFrame } from '../dist/index.js';

const v = JSON.parse(readFileSync(new URL('../../../protocol/crypto-vectors.json', import.meta.url)));
const bob = () => new Identity(v.app, v.group, 'bob', v.bob_secret, { alice: v.alice_public });
const alice = () => new Identity(v.app, v.group, 'alice', v.alice_secret, { bob: v.bob_public });

test('shared stream and offline vectors', () => {
  const aad = recordAAD(v.app, v.group, 'alice', 'bob', 'stream', v.id, 0);
  assert.equal(aad.toString(), v.stream_aad);
  const stream = new DecryptStream(v.stream_descriptor);
  assert.equal(stream.pull(Buffer.from(v.stream_ciphertext, 'hex'), aad).toString(), 'hello');
  assert.equal(stream.finished, true);
  assert.throws(() => stream.pull(Buffer.from(v.stream_ciphertext, 'hex'), aad), /final/);
  const tampered = Buffer.from(v.stream_ciphertext, 'hex'); tampered[3] ^= 1;
  assert.throws(() => new DecryptStream(v.stream_descriptor).pull(tampered, aad), /authentication/);
  assert.throws(() => new DecryptStream(v.stream_descriptor).pull(Buffer.from(v.stream_ciphertext, 'hex'), recordAAD(v.app, v.group, 'alice', 'bob', 'stream', v.id, 1)), /authentication/);
  const value = bob().open('alice', 'message', v.id, v.offline_message);
  assert.equal(value.expires, v.offline_expires);
  assert.throws(() => bob().openMessage('alice', v.id, v.offline_message), /Expired/);
  const later = bob().open('alice', 'message', v.id, alice().sealMessage('bob', v.id, Buffer.from('x'), 4102444800));
  assert.equal(later.expires, 4102444800);
  assert.throws(() => bob().open('alice', 'stream.open', v.id, v.message), /context/);
});

test('records reject reorder, duplication, tamper and data after FINAL', () => {
  const tx = new EncryptStream();
  const aad = seq => recordAAD('a', 'g', 'x', 'y', 'stream', v.id, seq);
  const records = [tx.push(Buffer.from('one'), aad(0)), tx.push(Buffer.alloc(65519, 7), aad(1)), tx.push(Buffer.alloc(0), aad(2), true)];
  assert.throws(() => tx.push(Buffer.from('late'), aad(3)), /finished/);
  assert.throws(() => new EncryptStream().push(Buffer.alloc(65520), aad(0)), /large/);
  assert.throws(() => new DecryptStream(tx.descriptor).pull(records[1], aad(1)));
  const rx = new DecryptStream(tx.descriptor);
  assert.equal(rx.pull(records[0], aad(0)).toString(), 'one');
  assert.throws(() => rx.pull(records[0], aad(1)), /authentication/);
  const rx2 = new DecryptStream(tx.descriptor);
  rx2.pull(records[0], aad(0));
  assert.equal(rx2.pull(records[1], aad(1)).length, 65519);
  assert.equal(rx2.pull(records[2], aad(2)).length, 0);
  assert.equal(rx2.finished, true);
  assert.throws(() => rx2.pull(records[2], aad(3)), /final/);
  assert.throws(() => new DecryptStream({ key: 'zz', header: '00' }), /descriptor/);
});

test('binary frame encoding', () => {
  const cipher = Buffer.alloc(17, 9);
  const frame = encodeFrame(v.id, 258, cipher);
  assert.equal(frame[0], 1); assert.equal(frame.length, 42);
  assert.deepEqual(decodeFrame(frame), { id: v.id, sequence: 258, cipher });
  assert.throws(() => decodeFrame(frame.subarray(0, 41)), /frame/);
  assert.throws(() => decodeFrame(Buffer.concat([Buffer.from([2]), frame.subarray(1)])), /frame/);
  assert.throws(() => encodeFrame(v.id, 0, Buffer.alloc(65537)), /large/);
});
