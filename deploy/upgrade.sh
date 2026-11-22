#!/usr/bin/env bash
# Server-side upgrade with rehearsal, backup and automatic rollback.
# Run as root:  STAGE=/tmp/cr-stage EXPECTED_SHA256=<sha> bash upgrade.sh
#   STAGE/common-relay  the new binary (uploaded by scripts/deploy-remote.sh)
# Optional env (defaults match deploy/common-relay.service):
#   SERVICE=common-relay BIN=/usr/local/bin/common-relay DATA=/var/lib/common-relay
#   BACKUP_ROOT=/var/backups/common-relay KEEP_DEPLOYS=5
#   ACCESS_FILE=/etc/common-relay/access-password.sha256 V2_ADMIN_FILE=/etc/common-relay/v2-admin.sha256
set -Eeuo pipefail
: "${STAGE:?STAGE required}" "${EXPECTED_SHA256:?EXPECTED_SHA256 required}"
SERVICE=${SERVICE:-common-relay}
BIN=${BIN:-/usr/local/bin/common-relay}
DATA=${DATA:-/var/lib/common-relay}
BACKUP_ROOT=${BACKUP_ROOT:-/var/backups/common-relay}
KEEP_DEPLOYS=${KEEP_DEPLOYS:-5}
ACCESS_FILE=${ACCESS_FILE:-/etc/common-relay/access-password.sha256}
V2_ADMIN_FILE=${V2_ADMIN_FILE:-/etc/common-relay/v2-admin.sha256}
NEW="$STAGE/common-relay"
HEALTH=http://127.0.0.1:47805/healthz

say() { printf '==> %s\n' "$*"; }
[[ $(id -u) == 0 ]] || { echo "run as root" >&2; exit 1; }
for t in sha256sum systemctl curl; do command -v $t >/dev/null; done
[[ $(sha256sum "$NEW" | cut -d' ' -f1) == "$EXPECTED_SHA256" ]] || { echo "checksum mismatch" >&2; exit 1; }
[[ $(systemctl is-active "$SERVICE") == active ]] || { echo "$SERVICE is not active; refusing to upgrade" >&2; exit 1; }
DATA=$(readlink -f "$DATA")
chmod 0755 "$NEW"
if cmp -s "$NEW" "$BIN"; then say "already running this binary"; exit 0; fi

ts=$(date -u +%Y%m%dT%H%M%SZ)
install -d -m 0700 "$BACKUP_ROOT" "$BACKUP_ROOT/deploys"
deploy="$BACKUP_ROOT/deploys/$ts"; install -d -m 0700 "$deploy"

say "snapshot live data (service keeps running)"
snap=$("$NEW" backup --data "$DATA" --out "$BACKUP_ROOT/pre-deploy" --keep "$KEEP_DEPLOYS")
echo "    $snap"

say "rehearse on a copy of the snapshot"
reh="$STAGE/rehearsal"; rm -rf "$reh"; cp -a "$snap" "$reh"
before=$("$NEW" schema --data "$reh")
"$NEW" check --data "$reh"
port=47917
args=(serve --data "$reh" --listen "127.0.0.1:$port" --disk-reserve 0 --access-password-file "$ACCESS_FILE")
[[ -s $V2_ADMIN_FILE ]] && args+=(--v2-admin-hash-file "$V2_ADMIN_FILE")
"$NEW" "${args[@]}" >"$STAGE/rehearsal.log" 2>&1 & rpid=$!
ok=0; for _ in $(seq 1 50); do curl -fsS "http://127.0.0.1:$port/healthz" >/dev/null 2>&1 && { ok=1; break; }; sleep 0.2; done
kill "$rpid" 2>/dev/null || true; wait "$rpid" 2>/dev/null || true
[[ $ok == 1 ]] || { echo "rehearsal server did not become healthy:" >&2; tail -20 "$STAGE/rehearsal.log" >&2; exit 1; }
if grep -qiE 'panic|fatal' "$STAGE/rehearsal.log"; then tail -20 "$STAGE/rehearsal.log" >&2; exit 1; fi
after=$("$NEW" schema --data "$reh")
rm -rf "$reh"
schema_changed=0; [[ $before != "$after" ]] && schema_changed=1
echo "    schema before=$before after=$after"

say "write rollback script"
cp -p "$BIN" "$deploy/common-relay.previous"
note="binary only (schema unchanged)"
if [[ $schema_changed == 1 ]]; then note="binary and the pre-deploy data snapshot (schema changed)"; fi
cat >"$deploy/rollback.sh" <<RB
#!/usr/bin/env bash
# Generated $ts. Restores the previous $note.
set -euo pipefail
systemctl stop $SERVICE
install -m 0755 "$deploy/common-relay.previous" "$BIN.rollback" && mv "$BIN.rollback" "$BIN"
if [[ $schema_changed == 1 ]]; then
  rm -rf "$DATA.after-$ts"; mv "$DATA" "$DATA.after-$ts"
  cp -a "$snap" "$DATA"; chmod 0700 "$DATA"
  echo "data written after the deploy kept in $DATA.after-$ts"
fi
systemctl start $SERVICE
curl -fsS --retry 15 --retry-connrefused --retry-delay 1 $HEALTH
RB
chmod 0700 "$deploy/rollback.sh"; bash -n "$deploy/rollback.sh"
printf '%s\n' "snapshot=$snap" "schema_before=$before" "schema_after=$after" "new_sha256=$EXPECTED_SHA256" \
  "previous_sha256=$(sha256sum "$BIN" | cut -d' ' -f1)" >"$deploy/deploy.info"

recover() { c=$?; trap - ERR; echo "!! upgrade failed, rolling back" >&2; "$deploy/rollback.sh" || true; exit $c; }
trap recover ERR
say "swap binary"
systemctl stop "$SERVICE"
install -m 0755 "$NEW" "$BIN.next" && mv "$BIN.next" "$BIN"
systemctl start "$SERVICE"
curl -fsS --retry 15 --retry-connrefused --retry-delay 1 "$HEALTH" >/dev/null
sleep 2
[[ $(systemctl is-active "$SERVICE") == active ]]
[[ $(sha256sum "$BIN" | cut -d' ' -f1) == "$EXPECTED_SHA256" ]]
trap - ERR

# keep the newest KEEP_DEPLOYS deploy records
ls -1d "$BACKUP_ROOT"/deploys/*/ 2>/dev/null | sort | head -n -"$KEEP_DEPLOYS" | xargs -r rm -rf
say "done: $(systemctl show "$SERVICE" -p ActiveState -p NRestarts | tr '\n' ' ')"
echo "rollback: $deploy/rollback.sh"
