import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const {advance,verify,member} = await import(process.env.COMMON_RELAY_GROUP_MODULE || '../dist/groups.js');
const v=JSON.parse(readFileSync(new URL('../../../protocol/group-vectors.json',import.meta.url)));
test('group signatures and transitions',()=>{
 verify(v.self_service,v.manager.signing_key); verify(v.initial,v.manager.signing_key); verify(v.request,v.new_member.signing_key);
 assert.equal(member(v.config,'Mac').signing_key,v.manager.signing_key);
 advance(v.initial,v.approved);advance(v.approved,v.removed);
 assert.throws(()=>advance(v.initial,v.removed));
 for(const key of ['renamed','left','disbanded']) { if(v[key]) advance(v.approved,v[key]); }
 for(const key of ['unauthorized_rename','unauthorized_disband']) assert.throws(()=>advance(v.approved,v[key]));
});
test('automatic admission vectors',()=>{advance(v.initial,v.auto_admission.approved);for(const c of v.auto_admission.invalid) assert.throws(()=>advance(v.initial,c.entry),c.case);});
test('strict payload vectors',()=>{for(const c of v.strict_payload.valid) assert.doesNotThrow(()=>advance(v.approved,c.entry),c.case);for(const c of v.strict_payload.invalid) assert.throws(()=>advance(v.approved,c.entry),c.case);for(const c of v.strict_payload.invalid_auto) assert.throws(()=>advance(v.initial,c.entry),c.case);});
