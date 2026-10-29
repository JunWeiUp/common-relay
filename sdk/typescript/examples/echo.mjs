// Local interoperability probe. Config must contain test identities and allow_local_test=true.
// Usage: node examples/echo.mjs CONFIG.json
// Echoes messages (offline ones are echoed offline and then acknowledged when `state_path`
// provides a journal) and echoes accepted streams record by record until the peer's FINAL record.
import { readFileSync } from 'node:fs';
import { Client, Identity, Journal } from '../dist/index.js';
const c=JSON.parse(readFileSync(process.argv[2], 'utf8'));
if (c.allow_local_test!==true) throw new Error('This probe is for isolated local tests only');
const identity=new Identity(c.app,c.group,c.device,c.secret_key,c.trusted_peers);
const journal=c.state_path ? new Journal(c.state_path) : undefined;
const client=await Client.connect(c.url,c.token,identity,{allowLocalTest:true,journal});
process.on('SIGTERM',()=>client.close());
async function echo(request) {
  const stream=await client.acceptStream(request);
  while (!stream.receivedFinal) { const data=await stream.receive(); await stream.send(data,stream.receivedFinal); }
}
try {
  for (let attempt=0; !(await client.peers()).some(peer=>peer.device==='python'); attempt++) {
    if (attempt>=100) throw new Error('Python peer missing');
    await new Promise(resolve=>setTimeout(resolve,100));
  }
  console.log('READY');
  while (true) {
    const event=await client.nextEvent();
    if (event.type==='stream.open') echo(event).catch(error=>{ console.error(error); process.exitCode=1; client.close(); });
    else if (event.type==='message') {
      await client.message(event.from,event.data,{offline:event.offline});
      if (event.offline) await client.acknowledge(event);
    }
  }
} catch(error) {
  if(error.message!=='Client closed') throw error;
} finally { client.close(); journal?.close(); }
