#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
command -v systemd-analyze >/dev/null 2>&1 || {
  echo "systemd-analyze is not available; unit verification skipped." >&2
  exit 0
}

staging="$(mktemp -d)"
cleanup() { rm -rf -- "$staging"; }
trap cleanup EXIT

for unit in "$ROOT_DIR"/deploy/*.service; do
  sed -E 's#^ExecStart=.*#ExecStart=/bin/true#' "$unit" > "$staging/$(basename "$unit")"
done
cp "$ROOT_DIR"/deploy/*.timer "$staging/"

systemd-analyze verify "$staging"/*.service "$staging"/*.timer
