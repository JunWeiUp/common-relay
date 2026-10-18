#!/usr/bin/env python3
"""Provision isolated interoperability identities. Prints no private credentials."""
import argparse,json,os,shlex,subprocess
from pathlib import Path
from nacl.public import PrivateKey
p=argparse.ArgumentParser();p.add_argument('--host',required=True);p.add_argument('--url',required=True);a=p.parse_args()
root=Path(__file__).resolve().parents[1]/'.local/qa';root.mkdir(parents=True,exist_ok=True);root.chmod(0o700)
names=['python','swift','java','dart'];configs={}
for name in names:
    file=root/(name+'.json')
    if file.exists():configs[name]=json.loads(file.read_text());continue
    key=PrivateKey.generate();configs[name]={'url':a.url,'app':'common-relay-qa','group':'interop','device':'qa-'+name,'secret_key':bytes(key).hex(),'public_key':bytes(key.public_key).hex(),'trusted_peers':{}}
    with os.fdopen(os.open(file,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'w') as f:json.dump(configs[name],f)
for name,config in configs.items():
    if 'token' not in config:
        remote='/root/common-relay-qa-'+name+'.credential.json'
        command=['/usr/local/bin/common-relay','device-add','--data','/var/lib/common-relay','--app',config['app'],'--group',config['group'],'--device',config['device'],'--public-key',config['public_key'],'--credential-out',remote]
        subprocess.run(['ssh','-o','BatchMode=yes',a.host,'sudo -n '+shlex.join(command)],check=True)
        result=subprocess.run(['ssh','-o','BatchMode=yes',a.host,'sudo -n cat '+shlex.quote(remote)],capture_output=True,check=True)
        config['token']=json.loads(result.stdout)['token']
    config['trusted_peers']={c['device']:c['public_key'] for other,c in configs.items() if other!=name}
    (root/(name+'.json')).write_text(json.dumps(config,indent=2)+'\n')
print('Provisioned 4 isolated QA identities; private configuration stays in .local/qa/.')
