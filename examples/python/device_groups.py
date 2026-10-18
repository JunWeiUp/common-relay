"""Create a group and join via manual and automatic compact invitations."""
import asyncio
import json
import os

from nacl.public import PrivateKey
from common_relay.groups import Groups
from local_server import local_server


def save_config(directory, group):
    # Persist credentials and retryable drafts in private application storage.
    path = directory / (group.config['device'] + '.private.json')
    temporary = path.with_suffix('.tmp')
    with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as file:
        json.dump(group.config, file)
        file.flush()
        os.fsync(file.fileno())
    os.replace(temporary, path)


async def main():
    async with local_server() as (directory, url):
        def device(name):
            key = PrivateKey.generate()
            return Groups({
                'url': url, 'app': 'example', 'device': name,
                'secret_key': bytes(key).hex(),
                'public_key': bytes(key.public_key).hex(), 'trusted_peers': {},
            }, allow_local_test=True)

        owner = device('owner')
        owner.prepare_create('Example devices', 'Owner')
        save_config(directory, owner)
        await owner.create()
        save_config(directory, owner)
        print('Signed group created')

        for mode in ('manual', 'auto'):
            invitation = await owner.invite(mode, compact=True)
            guest = device('guest-' + mode)
            # Passing the link locally models a trusted QR/link exchange.
            resolved = await guest.resolve_invitation(invitation['short_link'])
            guest.config['group'] = resolved['group']
            save_config(directory, guest)
            await guest.join(resolved, 'Guest ' + mode)
            save_config(directory, guest)
            if mode == 'manual':
                assert not await guest.finish_join()
                await owner.approve(invitation, await owner.pending(invitation))
                save_config(directory, owner)
            assert await guest.finish_join()
            save_config(directory, guest)
            await owner.refresh()
            save_config(directory, owner)
            print(mode + ' compact invitation joined and verified')


if __name__ == '__main__':
    asyncio.run(asyncio.wait_for(main(), 60))
