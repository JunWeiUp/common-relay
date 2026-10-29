import test from 'node:test';
import assert from 'node:assert/strict';
const { strict, REQUEST } = await import(process.env.COMMON_RELAY_PAYLOAD_MODULE || '../dist/payload.js');
const good = '{"version":1,"app":"example","group":"g","invitation":"i","member":{"device":"a","name":"A","public_key":"k","signing_key":"k","manager":false},"token_hash":"x"}';
test('strict payload rejects ambiguous JSON and invalid UTF-8', () => {
  assert.equal(strict(Buffer.from(good), REQUEST), true);
  for (const bad of [good.replace('"version":1','"version":1,"version":1'), good.replace('"version"','"\\u0076ersion"'),good.replace('"version":1','"Version":1'),good.replace('"version":1','"version":1e0'),good.replace('"version":1','"version":null'),good.replace('"name":"A"','"name":"\\ud800"'),good.replace('"name":"A"','"name":"\u0001"'),good.replace('"version":1','"version":9007199254740992')]) assert.equal(strict(Buffer.from(bad), REQUEST), false, bad);
  assert.equal(strict(Buffer.from([0xff]), REQUEST),false);
});
