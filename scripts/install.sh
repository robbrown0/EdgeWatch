#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/VERSION")"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BASE_DIR="/opt/edgewatch"
RELEASE_DIR="$BASE_DIR/releases/${VERSION}-${STAMP}"
CURRENT_LINK="$BASE_DIR/current"
CONFIG_DIR="/etc/edgewatch"
CONFIG_FILE="$CONFIG_DIR/config.toml"
SITE_FILE="$CONFIG_DIR/site.toml"
SECRETS_FILE="$CONFIG_DIR/secrets.toml"
DATA_DIR="/var/lib/edgewatch"
CONTROL_DIR="$DATA_DIR/control"
BACKUP_DIR="/var/backups/edgewatch"
PREVIOUS_TARGET=""
SWITCHED=0
UNITS_TOUCHED=0
UNIT_BACKUP_DIR=""
CONFIG_BACKUP=""
CONFIG_CREATED=0
SITE_BACKUP=""
SITE_CREATED=0
UNIT_NAMES=(
  edgewatch-agent.service
  edgewatch-web.service
  edgewatch-monitor-users.service
  edgewatch-geoip-update.service
  edgewatch-geoip-update.timer
)

log() { printf '\n[edgewatch] %s\n' "$*"; }
fail() { printf '\n[edgewatch] ERROR: %s\n' "$*" >&2; exit 1; }

restore_units() {
  [[ -n "$UNIT_BACKUP_DIR" && -d "$UNIT_BACKUP_DIR" ]] || return 0
  for unit in "${UNIT_NAMES[@]}"; do
    if [[ -f "$UNIT_BACKUP_DIR/$unit" ]]; then
      cp -a "$UNIT_BACKUP_DIR/$unit" "/etc/systemd/system/$unit"
    else
      rm -f "/etc/systemd/system/$unit"
    fi
  done
}

rollback() {
  local exit_code=$?
  trap - EXIT
  if [[ $exit_code -ne 0 ]]; then
    if [[ -n "$CONFIG_BACKUP" && -f "$CONFIG_BACKUP" ]]; then
      log "Restoring the pre-install configuration."
      cp -a "$CONFIG_BACKUP" "$CONFIG_FILE" || true
    elif [[ $CONFIG_CREATED -eq 1 ]]; then
      rm -f "$CONFIG_FILE" || true
    fi
    if [[ -n "$SITE_BACKUP" && -f "$SITE_BACKUP" ]]; then
      log "Restoring the pre-install private site configuration."
      cp -a "$SITE_BACKUP" "$SITE_FILE" || true
    elif [[ $SITE_CREATED -eq 1 ]]; then
      rm -f "$SITE_FILE" || true
    fi
    if [[ $UNITS_TOUCHED -eq 1 ]]; then
      restore_units || true
      systemctl daemon-reload || true
    fi
    if [[ $SWITCHED -eq 1 && -n "$PREVIOUS_TARGET" ]]; then
      log "Install failed after activation. Restoring the previous release."
      ln -sfn "$PREVIOUS_TARGET" "$CURRENT_LINK.rollback"
      mv -Tf "$CURRENT_LINK.rollback" "$CURRENT_LINK"
      systemctl daemon-reload || true
      systemctl restart edgewatch-agent.service edgewatch-web.service || true
      if [[ -f /etc/systemd/system/edgewatch-monitor-users.service ]]; then
        systemctl restart edgewatch-monitor-users.service || true
      else
        systemctl disable --now edgewatch-monitor-users.service 2>/dev/null || true
      fi
    elif [[ $SWITCHED -eq 1 ]]; then
      log "Initial install failed after activation. Disabling the incomplete release."
      systemctl disable --now edgewatch-agent.service edgewatch-web.service edgewatch-monitor-users.service 2>/dev/null || true
      rm -f "$CURRENT_LINK"
    fi
    if [[ -d "$RELEASE_DIR" && "$(readlink -f "$CURRENT_LINK" 2>/dev/null || true)" != "$RELEASE_DIR" ]]; then
      rm -rf -- "$RELEASE_DIR"
    fi
  fi
  [[ -n "$UNIT_BACKUP_DIR" ]] && rm -rf -- "$UNIT_BACKUP_DIR"
  exit "$exit_code"
}
trap rollback EXIT

[[ $EUID -eq 0 ]] || fail "Run this installer with sudo."
[[ -f "$ROOT_DIR/requirements.lock" ]] || fail "Run the installer from the extracted EdgeWatch package."
[[ "$VERSION" == "0.5.4" ]] || fail "Unexpected package version: $VERSION"

UNIT_BACKUP_DIR="$(mktemp -d)"
for unit in "${UNIT_NAMES[@]}"; do
  if [[ -f "/etc/systemd/system/$unit" ]]; then
    cp -a "/etc/systemd/system/$unit" "$UNIT_BACKUP_DIR/$unit"
  fi
done

if [[ -L "$CURRENT_LINK" ]]; then
  PREVIOUS_TARGET="$(readlink -f "$CURRENT_LINK")"
fi

log "Installing required Ubuntu packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  python3 python3-venv python3-pip curl ca-certificates \
  iproute2 wireguard-tools ufw apparmor-utils

if apt-cache show geoipupdate >/dev/null 2>&1; then
  apt-get install -y -qq geoipupdate
else
  log "Optional geoipupdate package is unavailable in the enabled repositories. The map can still be enabled with manually supplied MMDB files."
fi

python3 - <<'PY' || fail "Python 3.10 or newer is required."
import sys
raise SystemExit(0 if sys.version_info >= (3, 10) else 1)
PY

log "Creating the service account and protected directories"
getent group edgewatch >/dev/null || groupadd --system edgewatch
if ! id edgewatch >/dev/null 2>&1; then
  useradd --system --gid edgewatch --home-dir "$DATA_DIR" --shell /usr/sbin/nologin edgewatch
fi
install -d -o root -g edgewatch -m 0750 "$BASE_DIR" "$BASE_DIR/releases" "$CONFIG_DIR"
install -d -o root -g root -m 0700 "$BACKUP_DIR"
install -d -o root -g edgewatch -m 0770 "$DATA_DIR"
install -d -o edgewatch -g edgewatch -m 0770 "$CONTROL_DIR"
install -d -o root -g root -m 0755 /var/lib/GeoIP

log "Building the immutable release directory for EdgeWatch $VERSION"
install -d -o root -g edgewatch -m 0750 "$RELEASE_DIR"
cp -a "$ROOT_DIR/." "$RELEASE_DIR/"
rm -rf "$RELEASE_DIR/.venv" "$RELEASE_DIR"/.venv-* "$RELEASE_DIR/__pycache__" "$RELEASE_DIR/edgewatch/__pycache__" "$RELEASE_DIR/tests/__pycache__"

MAP_RELATIVE_PATH="edgewatch/static/maps/edgewatch.pmtiles"
if [[ -n "$PREVIOUS_TARGET"       && -f "$PREVIOUS_TARGET/$MAP_RELATIVE_PATH"       && ! -f "$RELEASE_DIR/$MAP_RELATIVE_PATH" ]]; then
  log "Preserving the existing local PMTiles archive"
  install -d "$RELEASE_DIR/$(dirname "$MAP_RELATIVE_PATH")"
  if ! ln "$PREVIOUS_TARGET/$MAP_RELATIVE_PATH" "$RELEASE_DIR/$MAP_RELATIVE_PATH" 2>/dev/null; then
    cp --reflink=auto "$PREVIOUS_TARGET/$MAP_RELATIVE_PATH" "$RELEASE_DIR/$MAP_RELATIVE_PATH"
  fi
fi
find "$RELEASE_DIR" -type d -exec chmod 0750 {} +
find "$RELEASE_DIR" -type f -exec chmod 0640 {} +
chmod 0750 "$RELEASE_DIR/scripts"/*.sh "$RELEASE_DIR/scripts/discover-identity.py"
python3 -m venv "$RELEASE_DIR/venv"
"$RELEASE_DIR/venv/bin/python" -m pip install \
  --disable-pip-version-check --no-cache-dir --no-deps \
  -r "$RELEASE_DIR/requirements.lock"
"$RELEASE_DIR/venv/bin/python" -m pip check
chown -R root:edgewatch "$RELEASE_DIR"

log "Running compilation, unit tests, and static safety checks"
PYTHONPATH="$RELEASE_DIR" "$RELEASE_DIR/venv/bin/python" -m compileall -q "$RELEASE_DIR/edgewatch" "$RELEASE_DIR/tests"
PYTHONPATH="$RELEASE_DIR" "$RELEASE_DIR/venv/bin/python" -m unittest discover -s "$RELEASE_DIR/tests" -v
for script in "$RELEASE_DIR"/scripts/*.sh; do
  bash -n "$script"
done
"$RELEASE_DIR/scripts/verify-units.sh"

log "Installing configuration templates"
install -o root -g edgewatch -m 0640 "$RELEASE_DIR/deploy/config.toml" "$CONFIG_DIR/config.toml.$VERSION.example"
install -o root -g edgewatch -m 0640 "$RELEASE_DIR/deploy/site.toml.example" "$CONFIG_DIR/site.toml.$VERSION.example"
install -o root -g edgewatch -m 0640 "$RELEASE_DIR/deploy/secrets.toml.example" "$CONFIG_DIR/secrets.toml.example"
if [[ -f "$CONFIG_FILE" ]]; then
  CONFIG_BACKUP="$BACKUP_DIR/config.toml.$STAMP"
  cp -a "$CONFIG_FILE" "$CONFIG_BACKUP"
  chown root:edgewatch "$CONFIG_FILE"
  chmod 0640 "$CONFIG_FILE"
  log "Existing configuration preserved. A backup is at $CONFIG_BACKUP"
else
  install -o root -g edgewatch -m 0640 "$RELEASE_DIR/deploy/config.toml" "$CONFIG_FILE"
  CONFIG_CREATED=1
  log "Installed the $VERSION starter configuration at $CONFIG_FILE"
fi

if [[ -f "$SITE_FILE" ]]; then
  SITE_BACKUP="$BACKUP_DIR/site.toml.$STAMP"
  cp -a "$SITE_FILE" "$SITE_BACKUP"
  chown root:edgewatch "$SITE_FILE"
  chmod 0640 "$SITE_FILE"
  log "Existing private site configuration preserved. A backup is at $SITE_BACKUP"
else
  install -o root -g edgewatch -m 0640 "$RELEASE_DIR/deploy/site.toml" "$SITE_FILE"
  SITE_CREATED=1
  log "Installed a neutral private site configuration at $SITE_FILE"
fi

log "Discovering safe Entra and oauth2-proxy identity metadata"
"$RELEASE_DIR/venv/bin/python" "$RELEASE_DIR/scripts/discover-identity.py" \
  --config "$CONFIG_FILE"
chown root:edgewatch "$CONFIG_FILE"
chmod 0640 "$CONFIG_FILE"
if [[ -f "$SECRETS_FILE" ]]; then
  chown root:root "$SECRETS_FILE"
  chmod 0600 "$SECRETS_FILE"
  log "Existing secrets file preserved."
else
  install -o root -g root -m 0600 "$RELEASE_DIR/deploy/secrets.toml" "$SECRETS_FILE"
  log "Installed an empty protected secrets file at $SECRETS_FILE"
fi

log "Validating configuration and secrets before activation"
if runuser -u edgewatch -- test -r "$SECRETS_FILE"; then
  fail "The unprivileged web account can read $SECRETS_FILE. Expected root:root mode 0600."
fi
PYTHONPATH="$RELEASE_DIR" "$RELEASE_DIR/venv/bin/python" - "$CONFIG_FILE" <<'PY'
import sys
from edgewatch.config import load_config, load_secrets
config = load_config(sys.argv[1])
load_secrets(config.secrets_path)
print(f"Validated interface={config.primary_interface} bind={config.bind_host}:{config.bind_port}")
PY

log "Initializing the dedicated finding-control database"
runuser -u edgewatch -- env PYTHONPATH="$RELEASE_DIR" "$RELEASE_DIR/venv/bin/python" - "$CONTROL_DIR/edgewatch-control.db" <<'PY'
import sys
from edgewatch.control import ControlStorage
ControlStorage(sys.argv[1]).initialize()
PY
find "$CONTROL_DIR" -maxdepth 1 -type f -name 'edgewatch-control.db*' -exec chown edgewatch:edgewatch {} + -exec chmod 0660 {} +

if [[ -n "$PREVIOUS_TARGET" && -x "$PREVIOUS_TARGET/scripts/backup.sh" ]]; then
  log "Creating a pre-upgrade backup without secrets"
  "$PREVIOUS_TARGET/scripts/backup.sh" "$BACKUP_DIR" >/dev/null
fi

log "Installing hardened systemd units"
UNITS_TOUCHED=1
install -o root -g root -m 0644 "$RELEASE_DIR/deploy/edgewatch-agent.service" /etc/systemd/system/edgewatch-agent.service
install -o root -g root -m 0644 "$RELEASE_DIR/deploy/edgewatch-web.service" /etc/systemd/system/edgewatch-web.service
install -o root -g root -m 0644 "$RELEASE_DIR/deploy/edgewatch-monitor-users.service" /etc/systemd/system/edgewatch-monitor-users.service
install -o root -g root -m 0644 "$RELEASE_DIR/deploy/edgewatch-geoip-update.service" /etc/systemd/system/edgewatch-geoip-update.service
install -o root -g root -m 0644 "$RELEASE_DIR/deploy/edgewatch-geoip-update.timer" /etc/systemd/system/edgewatch-geoip-update.timer

log "Activating the tested release"
ln -sfn "$RELEASE_DIR" "$CURRENT_LINK.new"
mv -Tf "$CURRENT_LINK.new" "$CURRENT_LINK"
SWITCHED=1
systemctl daemon-reload
systemctl enable edgewatch-agent.service edgewatch-web.service edgewatch-monitor-users.service
systemctl restart edgewatch-agent.service edgewatch-web.service edgewatch-monitor-users.service

log "Waiting for the collector, dashboard, and monitor-user helper health checks"
healthy=0
for _attempt in {1..90}; do
  dashboard_health="$(curl --silent --fail --max-time 2 http://127.0.0.1:8765/healthz 2>/dev/null || true)"
  if grep -Fq "\"version\":\"$VERSION\"" <<<"$dashboard_health" \
     && curl --silent --fail --max-time 2 http://127.0.0.1:8766/healthz >/dev/null; then
    healthy=1
    break
  fi
  sleep 1
done
if [[ $healthy -ne 1 ]]; then
  systemctl --no-pager --full status edgewatch-agent.service edgewatch-web.service edgewatch-monitor-users.service || true
  journalctl -u edgewatch-agent.service -u edgewatch-web.service -u edgewatch-monitor-users.service --since "10 minutes ago" --no-pager || true
  fail "The local dashboard did not become healthy. The previous release will be restored automatically."
fi

log "Cleaning old application releases, keeping the newest four"
mapfile -t releases < <(find "$BASE_DIR/releases" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' | sort -nr | awk '{print $2}')
if (( ${#releases[@]} > 4 )); then
  for old_release in "${releases[@]:4}"; do
    [[ "$old_release" == "$PREVIOUS_TARGET" ]] && continue
    rm -rf -- "$old_release"
  done
fi

SWITCHED=0
UNITS_TOUCHED=0
rm -rf -- "$UNIT_BACKUP_DIR"
UNIT_BACKUP_DIR=""
trap - EXIT

cat <<EOF_SUMMARY

EdgeWatch $VERSION is installed and healthy.

Local dashboard:    http://127.0.0.1:8765
Configuration:      $CONFIG_FILE
Private site config: $SITE_FILE
Secrets:            $SECRETS_FILE
New config sample:   $CONFIG_DIR/config.toml.$VERSION.example
New site sample:     $CONFIG_DIR/site.toml.$VERSION.example
Operations helper:  sudo $CURRENT_LINK/scripts/edgewatch-ctl.sh status
Live logs:           sudo journalctl -u edgewatch-agent -u edgewatch-web -u edgewatch-monitor-users -f

Next steps:
  1. Edit /etc/edgewatch/secrets.toml for Plex, ntfy, and Linode integrations.
  2. Optionally run sudo $CURRENT_LINK/scripts/configure-geoip.sh for the map.
  3. Add the authenticated Caddy and oauth2-proxy pattern from $CURRENT_LINK/deploy/Caddyfile.example.
  4. Create your dashboard DNS record and test HTTPS.

Do not open TCP port 8765 in UFW or the Linode Cloud Firewall.
See $CURRENT_LINK/INSTALL.md for the complete procedure.
EOF_SUMMARY
