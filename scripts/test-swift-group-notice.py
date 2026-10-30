#!/usr/bin/env python3
"""Deliver a group notice over a temporary loopback WebSocket to the Swift SDK."""
import argparse
import asyncio
import json
from pathlib import Path
import tempfile
from websockets.asyncio.server import serve

ROOT = Path(__file__).resolve().parents[1]


async def check(executable):
    vector = json.loads((ROOT / 'protocol/crypto-vectors.json').read_text())

    async def handler(socket):
        await socket.send(json.dumps({'type': 'welcome', 'version': 1, 'identity': {
            'app': 'example', 'group': 'test', 'device': 'alice', 'public_key': vector['alice_public']}}))
        await socket.send(json.dumps({'type': 'group.changed', 'revision': 42}))
        await socket.wait_closed()

    async with serve(handler, '127.0.0.1', 0, subprotocols=['common-relay.v1']) as server:
        port = server.sockets[0].getsockname()[1]
        with tempfile.TemporaryDirectory(prefix='relay-notice-test-') as directory:
            config = Path(directory) / 'config.json'
            config.write_text(json.dumps({
                'app': 'example', 'group': 'test', 'device': 'alice',
                'secret_key': vector['alice_secret'], 'trusted_peers': {},
                'url': f'ws://127.0.0.1:{port}/relay/v1/ws', 'token': 'x' * 64,
                'allow_local_test': True, 'group_notice_only': True}))
            config.chmod(0o600)
            process = await asyncio.create_subprocess_exec(
                executable, str(config), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            try:
                output, _ = await asyncio.wait_for(process.communicate(), 10)
            except BaseException:
                process.kill()
                await process.wait()
                raise
            assert process.returncode == 0 and b'GROUP_NOTICE 42' in output, output.decode()
            print('Swift real-WebSocket group.changed regression passed.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--swift', default=str(ROOT / 'sdk/swift/.build/debug/RelayProbe'))
    asyncio.run(check(parser.parse_args().swift))
