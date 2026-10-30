#!/usr/bin/env bash
# Invoked on the server as root with an explicit existing HTTPS site file.
set -euo pipefail
stage="$(cd "$(dirname "$0")/.." && pwd)"
site="${1:?Specify the existing Nginx HTTPS site file}"
test -f "$site"
# Validate before replacing any installed artifact.
for tool in python3 nginx systemctl curl; do command -v "$tool" >/dev/null; done
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) arch=amd64 ;;
  Linux/aarch64|Linux/arm64) arch=arm64 ;;
  *) echo 'Supported targets: Linux amd64 / arm64' >&2; exit 1 ;;
esac
binary="$stage/build/common-relay-linux-$arch"
test -f "$binary"
python3 - "$site" <<'PYTHON'
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
include = 'include /etc/nginx/snippets/common-relay.conf;'
if sum(line.strip() == include for line in text.splitlines()) > 1:
    raise SystemExit('Duplicate common-relay include')
if not any(line.strip() == include for line in text.splitlines()):
    if sum(line.strip() == '# common-relay:include' for line in text.splitlines()) != 1:
        raise SystemExit('Add one # common-relay:include marker inside the HTTPS server block')
PYTHON
backup="$(mktemp -d /root/common-relay-backup.XXXXXX)"
printf 'Backup: %s\n' "$backup"
cp -p "$site" "$backup/site.conf"
test ! -e /usr/local/bin/common-relay || cp -p /usr/local/bin/common-relay "$backup/common-relay"
test ! -e /etc/systemd/system/common-relay.service || cp -p /etc/systemd/system/common-relay.service "$backup/"
test ! -e /etc/nginx/snippets/common-relay.conf || cp -p /etc/nginx/snippets/common-relay.conf "$backup/"
install -m 0755 "$binary" /usr/local/bin/common-relay.next
mv /usr/local/bin/common-relay.next /usr/local/bin/common-relay
install -m 0644 "$stage/deploy/common-relay.service" /etc/systemd/system/common-relay.service
install -d -m 0755 /etc/nginx/snippets
install -m 0644 "$stage/deploy/nginx.conf" /etc/nginx/snippets/common-relay.conf

python3 - "$site" <<'PYTHON'
import sys
from pathlib import Path
p = Path(sys.argv[1])
text = p.read_text()
include = 'include /etc/nginx/snippets/common-relay.conf;'
if not any(line.strip() == include for line in text.splitlines()):
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.strip() == '# common-relay:include':
            indent = line[:len(line) - len(line.lstrip())]
            lines[i] = line.rstrip('\n') + '\n' + indent + include + '\n'
    p.write_text(''.join(lines))
PYTHON

if ! nginx -t; then cp -p "$backup/site.conf" "$site"; exit 1; fi
systemctl daemon-reload
systemctl enable --now common-relay
systemctl restart common-relay
curl --fail --retry 10 --retry-connrefused --retry-delay 1 http://127.0.0.1:47805/healthz
systemctl reload nginx
systemctl show common-relay -p ActiveState -p MemoryCurrent
