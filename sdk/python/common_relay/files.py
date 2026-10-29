"""Encrypted staged files. Keep the encrypted staging file to resume uploads."""
import hashlib
import json
import os
import struct
import uuid
from pathlib import Path
import httpx
from .crypto import EncryptStream, DecryptStream, stream_aad

def prepare(identity, recipient, source, staged, metadata=None):
    object_id = uuid.uuid4().hex
    crypt = EncryptStream()
    descriptor = crypt.descriptor()
    descriptor['metadata'] = metadata or {'name': Path(source).name}
    digest = hashlib.sha256()
    with open(source,'rb') as inp, open(staged,'xb') as out:
        os.chmod(staged,0o600)
        seq = 0
        while True:
            data = inp.read(65519)
            cipher = crypt.push(data,stream_aad(identity,identity.device,recipient,object_id,seq,'file'),final=not data)
            record=struct.pack('>I',len(cipher))+cipher
            out.write(record)
            digest.update(record)
            seq+=1
            if not data:
                break
    return {'id':object_id,'to':recipient,'size':os.path.getsize(staged),'metadata':identity.seal(recipient,'file',object_id,descriptor),'sha256':digest.hexdigest()}

def decrypt(identity, sender, info, staged, destination):
    descriptor=identity.open(sender,'file',info['id'],info['metadata'])
    crypt=DecryptStream(descriptor)
    with open(staged,'rb') as encrypted:
        if hashlib.file_digest(encrypted,'sha256').hexdigest()!=info['sha256']:
            raise ValueError('Ciphertext digest mismatch')
    destination=Path(destination)
    temporary=destination.with_name(destination.name+'.'+uuid.uuid4().hex+'.partial')
    try:
        with open(staged,'rb') as inp, open(temporary,'xb') as out:
            os.chmod(temporary,0o600)
            seq=0
            while prefix:=inp.read(4):
                if len(prefix)!=4:
                    raise ValueError('Truncated record')
                size=struct.unpack('>I',prefix)[0]
                if not 17<=size<=65536:
                    raise ValueError('Invalid record size')
                cipher=inp.read(size)
                if len(cipher)!=size:
                    raise ValueError('Truncated ciphertext')
                out.write(crypt.pull(cipher,stream_aad(identity,sender,identity.device,info['id'],seq,'file')))
                seq+=1
            if not crypt.finished:
                raise ValueError('Missing authenticated final record')
            out.flush()
            os.fsync(out.fileno())
        # Never silently replace an existing application file.
        os.link(temporary,destination)
        return descriptor['metadata']
    finally:
        temporary.unlink(missing_ok=True)

class Files:
    def __init__(self,url,token,*,allow_local_test=False):
        parsed=httpx.URL(url)
        if parsed.scheme!='https' and not (allow_local_test and parsed.scheme=='http' and parsed.host in ('127.0.0.1','localhost')):
            raise ValueError('HTTPS required')
        self.http=httpx.AsyncClient(base_url=url.rstrip('/')+'/',headers={'Authorization':'Bearer '+token},timeout=60,follow_redirects=False,trust_env=False)

    async def close(self):
        await self.http.aclose()

    async def upload(self,info,staged):
        response=await self.http.post('',json=info)
        if response.status_code==409:
            response=await self.http.get(info['id'])
            response.raise_for_status()
            existing=response.json()
            if any(existing.get(k)!=info.get(k) for k in ('id','to','size','metadata','sha256')):
                raise ValueError('Upload ID conflict')
        else:
            response.raise_for_status()
        status=response.json()
        if any(status.get(k)!=info.get(k) for k in ('id','to','size','metadata','sha256')):
            raise ValueError('Upload ID conflict')
        offset=status['offset']
        if type(offset) is not int or not 0<=offset<=info['size']:
            raise ValueError('Invalid upload offset')
        with open(staged,'rb') as inp:
            inp.seek(offset)
            while data:=inp.read(1<<20):
                response=await self.http.put(info['id']+'/data',content=data,headers={'Upload-Offset':str(offset)})
                response.raise_for_status()
                next_offset=response.json()['offset']
                if type(next_offset) is not int or next_offset!=offset+len(data) or next_offset>info['size']:
                    raise ValueError('Invalid upload progress')
                offset=next_offset
        response=await self.http.post(info['id']+'/commit')
        response.raise_for_status()
        return response.json()

    async def inbox(self):
        response=await self.http.get('')
        response.raise_for_status()
        return response.json()

    async def download(self,info,staged):
        offset=Path(staged).stat().st_size if Path(staged).exists() else 0
        if not 0<=offset<=info['size']:
            raise ValueError('Staged file exceeds declared size')
        if offset==info['size']:
            return
        async with self.http.stream('GET',info['id']+'/data',headers={'Range':f'bytes={offset}-'}) as response:
            response.raise_for_status()
            if offset and response.status_code!=206:
                raise ValueError('Range not honored')
            with open(staged,'ab') as out:
                os.chmod(staged,0o600)
                async for data in response.aiter_bytes():
                    if out.tell()+len(data)>info['size']:
                        raise ValueError('Download exceeds declared size')
                    out.write(data)

    async def acknowledge(self,object_id):
        response=await self.http.delete(object_id)
        response.raise_for_status()
