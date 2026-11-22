"""Regression checks retained when removing the shared Rust experiment."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import httpx
from common_relay.client import Client
from common_relay.files import Files

class NativeLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_group_change_is_delivered_to_application(self):
        import json
        identity=SimpleNamespace(app='example',group='test',device='alice')
        client=Client('ws://127.0.0.1/v2/ws','x'*64,identity,allow_local_test=True)
        async def frames():
            yield json.dumps({'type':'group.changed','revision':2})
        class Socket:
            def __aiter__(self): return frames()
            async def close(self): pass
        client.ws=Socket()
        await client._read()
        event=client.events.get_nowait()
        self.assertEqual(event['type'],'group.changed')
        self.assertEqual(event['revision'],2)

    async def test_bad_upload_offsets_do_not_advance(self):
        info={'id':'01'*16,'to':'peer','size':3,'metadata':'encrypted','sha256':'digest'}
        for offset,progress in ((-1,None),(4,None),(0,0),(0,4)):
            with self.subTest(offset=offset,progress=progress), tempfile.TemporaryDirectory() as directory:
                path=Path(directory)/'staged';path.write_bytes(b'abc')
                requests=[]
                def respond(request):
                    requests.append(request)
                    if request.method=='POST':return httpx.Response(201,json={**info,'offset':offset})
                    return httpx.Response(200,json={'offset':progress})
                files=Files('http://127.0.0.1/v2/files','test',allow_local_test=True)
                await files.http.aclose()
                files.http=httpx.AsyncClient(base_url='http://127.0.0.1/v2/files/',transport=httpx.MockTransport(respond))
                try:
                    with self.assertRaises(ValueError):await files.upload(info,path)
                    self.assertFalse(any(str(r.url).endswith('/commit') for r in requests))
                finally:await files.close()

    async def test_oversized_staging_file_rejected_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'staged';path.write_bytes(b'abc')
            files=Files('http://127.0.0.1/v2/files','test',allow_local_test=True)
            try:
                with self.assertRaises(ValueError):await files.download({'size':2},path)
            finally:await files.close()
