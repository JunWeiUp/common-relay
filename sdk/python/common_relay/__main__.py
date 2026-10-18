"""Local device identity creation; private keys never go to the relay server."""
import argparse
import json
import os
from pathlib import Path
from nacl.public import PrivateKey

def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='command',required=True)
    create=sub.add_parser('keygen');create.add_argument('--app',required=True);create.add_argument('--group',required=True);create.add_argument('--device',required=True);create.add_argument('--output',type=Path,required=True);create.add_argument('--url',required=True)
    public=sub.add_parser('public-key');public.add_argument('config',type=Path)
    args=p.parse_args()
    if args.command=='keygen':
        key=PrivateKey.generate();config={'url':args.url,'app':args.app,'group':args.group,'device':args.device,'secret_key':bytes(key).hex(),'public_key':bytes(key.public_key).hex(),'trusted_peers':{}}
        fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as f:json.dump(config,f,indent=2);f.write('\n')
        print(config['public_key'])
    else:
        data=json.loads(args.config.read_text());print(bytes(PrivateKey(bytes.fromhex(data['secret_key'])).public_key).hex())

if __name__=='__main__':main()
