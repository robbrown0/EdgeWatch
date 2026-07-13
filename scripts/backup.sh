#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
INCLUDE_SECRETS=0
if [[ "${1:-}" == "--include-secrets" ]]; then
  INCLUDE_SECRETS=1
  shift
fi
DESTINATION="${1:-/var/backups/edgewatch}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
CURRENT="/opt/edgewatch/current"
DATA="/var/lib/edgewatch"
RUNTIME="/run/edgewatch"
STAGING="$(mktemp -d)"
cleanup() { rm -rf -- "$STAGING"; }
trap cleanup EXIT

[[ -x "$CURRENT/venv/bin/python" ]] || { echo "EdgeWatch runtime was not found." >&2; exit 1; }
install -d -m 0700 -o root -g root "$DESTINATION"
install -d -m 0750 "$STAGING/etc/edgewatch" "$STAGING/var/lib/edgewatch" "$STAGING/var/lib/edgewatch/control" "$STAGING/opt/edgewatch/current"

if [[ -f /etc/edgewatch/config.toml ]]; then
  cp -a /etc/edgewatch/config.toml "$STAGING/etc/edgewatch/"
fi
if [[ -f /etc/edgewatch/site.toml ]]; then
  cp -a /etc/edgewatch/site.toml "$STAGING/etc/edgewatch/"
fi
if [[ $INCLUDE_SECRETS -eq 1 && -f /etc/edgewatch/secrets.toml ]]; then
  cp -a /etc/edgewatch/secrets.toml "$STAGING/etc/edgewatch/"
fi
if [[ -f "$RUNTIME/latest.json" ]]; then
  cp -a "$RUNTIME/latest.json" "$STAGING/var/lib/edgewatch/"
fi
if [[ -f "$DATA/edgewatch.db" ]]; then
  "$CURRENT/venv/bin/python" - "$DATA/edgewatch.db" "$STAGING/var/lib/edgewatch/edgewatch.db" <<'PY'
import sqlite3
import sys

source_path, destination_path = sys.argv[1:3]
source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True, timeout=10.0)
destination = sqlite3.connect(destination_path, timeout=10.0)
try:
    source.backup(destination)
finally:
    destination.close()
    source.close()
PY
fi
if [[ -f "$DATA/control/edgewatch-control.db" ]]; then
  "$CURRENT/venv/bin/python" - "$DATA/control/edgewatch-control.db" "$STAGING/var/lib/edgewatch/control/edgewatch-control.db" <<'PY'
import sqlite3
import sys

source_path, destination_path = sys.argv[1:3]
source = sqlite3.connect(f"file:{source_path}?mode=ro", uri=True, timeout=10.0)
destination = sqlite3.connect(destination_path, timeout=10.0)
try:
    source.backup(destination)
finally:
    destination.close()
    source.close()
PY
fi
cp -a "$CURRENT/deploy" "$STAGING/opt/edgewatch/current/"
cp -a "$CURRENT/VERSION" "$STAGING/opt/edgewatch/current/"

archive="$DESTINATION/edgewatch-$STAMP.tar.gz"
tar --create --gzip --file "$archive" --directory "$STAGING" .
if [[ $INCLUDE_SECRETS -eq 1 ]]; then
  chmod 0600 "$archive"
  chown root:root "$archive"
  echo "WARNING: This unencrypted archive contains EdgeWatch secrets. Protect it accordingly." >&2
else
  chmod 0600 "$archive"
  chown root:root "$archive"
fi
echo "$archive"
