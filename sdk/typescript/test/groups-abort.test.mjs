// Caller-supplied AbortSignal cancels group requests, including invitation resolution.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { Groups, makeInvitationLink } from '../dist/index.js';

async function hangingServer() {
  const state = { hits: 0, started: null };
  let notify;
  state.started = new Promise((resolve) => { notify = resolve; });
  const server = createServer(() => { state.hits++; notify(); });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  state.url = `ws://127.0.0.1:${server.address().port}/relay/v1/ws`;
  state.close = () => { server.closeAllConnections(); server.close(); };
  return state;
}

test('aborting the signal stops an in-flight group request', async () => {
  const s = await hangingServer();
  try {
    const controller = new AbortController();
    const request = new Groups({ url: s.url, app: 'test', device: 'test' }, { allowLocalTest: true }).withSignal(controller.signal).call('GET', '/group');
    await s.started;
    controller.abort();
    await assert.rejects(request, { name: 'AbortError' });
  } finally { s.close(); }
});

test('aborted invitation resolution never contacts the relay', async () => {
  const s = await hangingServer();
  try {
    const link = makeInvitationLink({ url: s.url, id: 'a'.repeat(32) }, new Uint8Array(32));
    const groups = new Groups({ url: s.url, app: 'example' }, { allowLocalTest: true });
    await assert.rejects(groups.withSignal(AbortSignal.abort()).resolveInvitation(link), { name: 'AbortError' });
    assert.equal(s.hits, 0);
  } finally { s.close(); }
});
