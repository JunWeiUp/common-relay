import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const { readToken, sealInvitation, openInvitation, makeInvitationLink, parseInvitationLink } = await import(process.env.COMMON_RELAY_INVITATION_MODULE || '../dist/invitation-links.js');

const v = JSON.parse(readFileSync(new URL('../../../protocol/invitation-link-vectors.json', import.meta.url)));
const key = Buffer.from(v.key, 'hex');
const nonce = Buffer.from(v.nonce, 'hex');
test('compact invitation shared vector', () => {
  assert.equal(readToken(key), v.read_token);
  assert.equal(sealInvitation(v.invitation, key, nonce), v.packet);
  assert.deepEqual(openInvitation(v.packet, key), v.invitation);
  assert.equal(makeInvitationLink(v.invitation, key), v.link);
  const parsed = parseInvitationLink(v.link);
  assert.equal(parsed.url, v.invitation.url);
  assert.equal(parsed.id, v.invitation.id);
  assert.deepEqual(Buffer.from(parsed.key), key);
});
test('reject corrupted compact invitation', () => {
  assert.throws(() => openInvitation(v.packet, Buffer.alloc(32)));
  assert.throws(() => parseInvitationLink(v.link + '?bad'));
});
test('compact invitation carrying the server access password', () => {
  assert.equal(makeInvitationLink(v.invitation, key, v.access_password), v.link_with_password);
  const parsed = parseInvitationLink(v.link_with_password);
  assert.equal(parsed.password, v.access_password);
  assert.deepEqual(Buffer.from(parsed.key), key);
  assert.equal(parsed.id, v.invitation.id);
  assert.equal(parseInvitationLink(v.link).password, undefined);
  for (const suffix of v.invalid_link_suffixes) assert.throws(() => parseInvitationLink(v.link + suffix), /Invalid compact invitation/, suffix);
});
