"""Shared local-only lifecycle for the runnable examples."""
import asyncio
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
        process = subprocess.Popen([
            str(binary), 'serve', '--data', directory + '/server',
            '--listen', f'127.0.0.1:{port}', '--self-service-apps', 'example',
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
            yield Path(directory), f'ws://127.0.0.1:{port}/relay/v1/ws'
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
