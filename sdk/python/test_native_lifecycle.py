"""Regression checks retained when removing the shared Rust experiment."""
import asyncio
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock
import httpx
from common_relay.client import Stream, RelayError
from common_relay.files import Files

class NativeLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_close_unblocks_reader_and_is_idempotent(self):
        client=SimpleNamespace(streams={},send_event=AsyncMock())
        stream=Stream(client,'peer','01'*16,None)
        client.streams[stream.id]=stream
        reader=asyncio.create_task(stream.receive())
        await asyncio.sleep(0)
        await stream.close()
        with self.assertRaises(RelayError):await asyncio.wait_for(reader,1)
        await stream.close()
        self.assertNotIn(stream.id,client.streams)
        self.assertEqual(client.send_event.await_count,1)

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
                files=Files('http://127.0.0.1/relay/v1/files','test',allow_local_test=True)
                await files.http.aclose()
                files.http=httpx.AsyncClient(base_url='http://127.0.0.1/relay/v1/files/',transport=httpx.MockTransport(respond))
                try:
                    with self.assertRaises(ValueError):await files.upload(info,path)
                    self.assertFalse(any(str(r.url).endswith('/commit') for r in requests))
                finally:await files.close()

    async def test_oversized_staging_file_rejected_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'staged';path.write_bytes(b'abc')
            files=Files('http://127.0.0.1/relay/v1/files','test',allow_local_test=True)
            try:
                with self.assertRaises(ValueError):await files.download({'size':2},path)
            finally:await files.close()
