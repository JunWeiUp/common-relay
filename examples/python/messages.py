"""Run from the repository: .venv/bin/python examples/python/messages.py"""
import asyncio
import json
import subprocess

from nacl.public import PrivateKey
from common_relay import Client, Identity
from local_server import ROOT, local_server


async def main():
    async with local_server() as (directory, url):
        keys = {name: PrivateKey.generate() for name in ('alice', 'bob')}
        identities, tokens = {}, {}
        for name, key in keys.items():
            # Both endpoints are controlled here: pin public keys directly.
            # Real applications must exchange them over a trusted channel.
            peers = {peer: bytes(value.public_key).hex()
                     for peer, value in keys.items() if peer != name}
            identities[name] = Identity('example', 'messages', name, bytes(key).hex(), peers)
            credential = directory / (name + '.json')
            subprocess.run([
                str(ROOT / 'build/common-relay'), 'device-add',
                '--data', str(directory / 'server'), '--app', 'example',
                '--group', 'messages', '--device', name,
                '--public-key', identities[name].public_key,
                '--credential-out', str(credential),
            ], check=True)
            tokens[name] = json.loads(credential.read_text())['token']

        def client(name):
            return Client(url, tokens[name], identities[name], directory / (name + '.db'),
                          allow_local_test=True)

        async with client('alice') as alice:
            stored = await alice.message('bob', b'Hello while offline', offline=True)
            assert stored['type'] == 'stored'
            async with client('bob') as bob:
                event = await asyncio.wait_for(bob.events.get(), 10)
                assert event['data'] == b'Hello while offline'
                await bob.acknowledge(event)
                print('Offline message received and acknowledged')

                await alice.send_online('bob', b'Hello online')
                event = await asyncio.wait_for(bob.events.get(), 10)
                assert event['data'] == b'Hello online'
                print('Online message received')

                opening = asyncio.create_task(alice.open_stream('bob'))
                try:
                    request = await asyncio.wait_for(bob.events.get(), 10)
                    incoming = await bob.accept_stream(request)
                    outgoing = await opening
                finally:
                    if not opening.done():
                        opening.cancel()
                    await asyncio.gather(opening, return_exceptions=True)
                await outgoing.send(b'Hello stream', final=True)
                assert await incoming.receive() == b'Hello stream'
                await incoming.send(b'Hello back', final=True)
                assert await outgoing.receive() == b'Hello back'
                await outgoing.close()
                print('Encrypted stream verified in both directions')


if __name__ == '__main__':
    asyncio.run(asyncio.wait_for(main(), 60))
