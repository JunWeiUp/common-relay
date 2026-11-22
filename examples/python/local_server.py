"""Shared local-only lifecycle for the runnable examples."""
import asyncio
import hashlib
import secrets
from contextlib import asynccontextmanager
from pathlib import Path
import socket
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]


@asynccontextmanager
async def local_server():
    binary = ROOT / 'build/common-relay'
    if not binary.is_file():
        raise SystemExit('Run: go build -o build/common-relay ./cmd/common-relay')
    with tempfile.TemporaryDirectory(prefix='common-relay-example-') as directory:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        # The server requires an access password and a v2 admin secret; both are random per run.
        access = 'example-' + secrets.token_hex(8)
        (Path(directory) / 'access.sha256').write_text(hashlib.sha256(access.encode()).hexdigest())
        admin = Path(directory) / 'admin.sha256'
        admin.write_text(hashlib.sha256(secrets.token_hex(32).encode()).hexdigest())
        process = subprocess.Popen([
            str(binary), 'serve', '--data', directory + '/server',
            '--listen', f'127.0.0.1:{port}', '--self-service-apps', 'example',
            '--access-password-file', directory + '/access.sha256', '--v2-admin-hash-file', str(admin),
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError('Example relay exited before becoming ready')
                try:
                    _, writer = await asyncio.open_connection('127.0.0.1', port)
                    writer.close()
                    await writer.wait_closed()
                    break
                except OSError:
                    await asyncio.sleep(0.05)
            else:
                raise TimeoutError('Example relay startup timed out')
            yield Path(directory), f'ws://127.0.0.1:{port}/v2/ws', access
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
