import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
import { checkAccessPassword } from './access.js';

const purpose = 'common-relay/invitation-link/v1';
const b64url = (value: Uint8Array) => Buffer.from(value).toString('base64url');
function decode(text: string, size: number): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(text)) throw new Error('Invalid compact invitation');
  const result = Buffer.from(text, 'base64url');
  if (result.length !== size || b64url(result) !== text) throw new Error('Invalid compact invitation');
  return result;
}
export function readToken(key: Uint8Array): string {
  if (key.length !== 32) throw new Error('Invalid key');
  return createHash('sha256').update('common-relay/invitation-link/read/v1\0').update(key).digest('hex');
}
export function sealInvitation(invitation: Record<string, unknown>, key: Uint8Array, nonce: Uint8Array): string {
  const plain = Buffer.from(JSON.stringify({ version: 1, purpose, invitation }));
  return Buffer.concat([Buffer.from(nonce), Buffer.from(nacl.secretbox(plain, nonce, key))]).toString('base64');
}
export function openInvitation(packet: string, key: Uint8Array): Record<string, unknown> {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(packet)) throw new Error('Invalid packet');
  const raw = Buffer.from(packet, 'base64');
  if (raw.toString('base64') !== packet || raw.length < 40 || raw.length > 16384) throw new Error('Invalid packet');
  const plain = nacl.secretbox.open(raw.subarray(24), raw.subarray(0, 24), key);
  if (!plain) throw new Error('Invalid packet');
  const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plain));
  if (value?.version !== 1 || value.purpose !== purpose || !value.invitation || typeof value.invitation !== 'object' || Array.isArray(value.invitation)) throw new Error('Invalid packet scope');
  return value.invitation;
}
/** `password` (optional server access password) is appended to the fragment as `.base64url(ASCII)`; fragments never reach HTTP. */
export function makeInvitationLink(invitation: { url: string; id: string }, key: Uint8Array, password?: string): string {
  if (!/^[a-f0-9]{32}$/.test(invitation.id) || key.length !== 32) throw new Error('Invalid invitation');
  const access = checkAccessPassword(password);
  const suffix = access === undefined ? '' : '.' + b64url(Buffer.from(access, 'ascii'));
  return `common-relay://${new URL(invitation.url).host}/i/${b64url(Buffer.from(invitation.id, 'hex'))}#${b64url(key)}${suffix}`;
}
function fragmentPassword(text: string): string {
  if (!/^[A-Za-z0-9_-]+$/.test(text)) throw new Error('Invalid compact invitation');
  const raw = Buffer.from(text, 'base64url');
  if (b64url(raw) !== text || raw.some(b => b > 0x7f)) throw new Error('Invalid compact invitation');
  try { return checkAccessPassword(raw.toString('ascii'))!; } catch { throw new Error('Invalid compact invitation'); }
}
export function parseInvitationLink(text: string, allowLocalTest = false): { url: string; id: string; key: Uint8Array; password?: string } {
  if (text.length > 2048 || text.includes('%') || text.includes('?')) throw new Error('Invalid compact invitation');
  const u = new URL(text);
  if (u.protocol !== 'common-relay:' || !u.hostname || u.username || u.password || !/^\/i\/[A-Za-z0-9_-]{22}$/.test(u.pathname)) throw new Error('Invalid compact invitation');
  const fragment = u.hash.slice(1), dot = fragment.indexOf('.');
  const result: { url: string; id: string; key: Uint8Array; password?: string } = { url: `${allowLocalTest && u.hostname === '127.0.0.1' ? 'ws' : 'wss'}://${u.host}/relay/v1/ws`, id: decode(u.pathname.slice(3), 16).toString('hex'), key: decode(dot < 0 ? fragment : fragment.slice(0, dot), 32) };
  if (dot >= 0) result.password = fragmentPassword(fragment.slice(dot + 1));
  return result;
}
