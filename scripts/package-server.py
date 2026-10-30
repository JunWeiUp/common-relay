#!/usr/bin/env python3
"""Build self-contained Linux deployment archives without private state."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True, help='Release tag or local candidate name')
    parser.add_argument('--arch', choices=('amd64', 'arm64'), action='append')
    parser.add_argument('--output', type=Path, default=ROOT / 'build/server-release')
    args = parser.parse_args()
    if not re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.-]+)?', args.version):
        parser.error('version must be X.Y.Z or vX.Y.Z, optionally with a prerelease suffix')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=ROOT))
    archives = []
    for arch in dict.fromkeys(args.arch or ['amd64', 'arm64']):
        name = f'common-relay-server-{args.version}-linux-{arch}'
        with tempfile.TemporaryDirectory(prefix='common-relay-package-') as temp:
            stage = Path(temp) / name
            (stage / 'build').mkdir(parents=True)
            binary = stage / 'build' / f'common-relay-linux-{arch}'
            subprocess.run(['go', 'build', '-trimpath', '-o', str(binary), './cmd/common-relay'],
                           cwd=ROOT, env={**os.environ, 'CGO_ENABLED': '0', 'GOOS': 'linux', 'GOARCH': arch}, check=True)
            shutil.copytree(ROOT / 'deploy', stage / 'deploy')
            (stage / 'docs').mkdir()
            for doc in ('DEPLOYMENT.md', 'DEVICE-GROUPS.md'):
                shutil.copy2(ROOT / 'docs' / doc, stage / 'docs' / doc)
            (stage / 'protocol').mkdir()
            shutil.copy2(ROOT / 'protocol/README.md', stage / 'protocol/README.md')
            shutil.copy2(ROOT / 'LICENSE', stage / 'LICENSE')
            (stage / 'README.txt').write_text(
                f'Common Relay server {args.version} / linux-{arch}\n'
                'See docs/DEPLOYMENT.md for installation, configuration, backup and rollback.\n'
                'Requires Linux, systemd, Nginx, an existing HTTPS site, Python 3 and curl.\n'
                'Verify the archive against the Release SHA256SUMS before extracting.\n'
                'Add # common-relay:include inside your HTTPS server block, then run as root:\n'
                '  bash deploy/install.sh /etc/nginx/sites-available/relay.conf\n')
            files = {str(p.relative_to(stage)): hashlib.sha256(p.read_bytes()).hexdigest()
                     for p in sorted(stage.rglob('*')) if p.is_file()}
            (stage / 'SOURCE.json').write_text(json.dumps({
                'version': args.version, 'commit': commit, 'dirty': dirty,
                'source': 'https://github.com/JunWeiUp/common-relay',
                'target': f'linux/{arch}', 'files': files,
            }, indent=2) + '\n')
            archive = output / f'{name}.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                tar.add(stage, arcname=name)
            archives.append(archive)
            print(archive)
    (output / 'SHA256SUMS').write_text(''.join(
        f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in archives))


if __name__ == '__main__':
    main()
