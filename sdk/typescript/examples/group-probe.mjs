import { readFile, writeFile } from 'node:fs/promises';
const { Groups } = await import(process.env.COMMON_RELAY_GROUP_MODULE || '../dist/groups.js');
const path = process.argv[2];
const c = JSON.parse(await readFile(path, 'utf8'));
const g = new Groups(c, { allowLocalTest: true });
let result = {};
switch (c.group_action) {
  case 'rename': await g.rename(c.device, 'Updated device'); break;
  case 'leave': await g.leave(); break;
  case 'disband': await g.disband(); break;
  case 'create': delete c.group; g.prepareCreate('My devices', 'Creator'); await g.create(); break;
  case 'join': await g.join(c.invitation_link == null ? c.invitation : await g.resolveInvitation(c.invitation_link), c.device); break;
  case 'finish': result = await g.finishJoin(); break;
  case 'invite': result = await g.invite(c.invite_mode ?? 'manual', { compact: c.compact === true }); break;
  case 'approve': await g.approve(c.invitation, c.request); break;
  case 'remove': await g.remove(c.remove); break;
  default: result = await g.refresh();
}
c.result = result;
await writeFile(path, JSON.stringify(c));
