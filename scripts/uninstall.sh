#!/usr/bin/env bash
set -Eeuo pipefail

[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }
purge="${1:-}"
systemctl disable --now edgewatch-agent.service edgewatch-web.service edgewatch-monitor-users.service edgewatch-geoip-update.timer 2>/dev/null || true
rm -f \
  /etc/systemd/system/edgewatch-agent.service \
  /etc/systemd/system/edgewatch-web.service \
  /etc/systemd/system/edgewatch-monitor-users.service \
  /etc/systemd/system/edgewatch-geoip-update.service \
  /etc/systemd/system/edgewatch-geoip-update.timer
systemctl daemon-reload
rm -rf /opt/edgewatch /run/edgewatch
if [[ "$purge" == "--purge" ]]; then
  rm -rf /etc/edgewatch /var/lib/edgewatch
  userdel edgewatch 2>/dev/null || true
  groupdel edgewatch 2>/dev/null || true
  echo "EdgeWatch application, data, configuration, and service account removed."
  echo "/var/lib/GeoIP and /etc/GeoIP.conf were preserved because they may be shared."
else
  echo "EdgeWatch application removed. Configuration, history, backups, and GeoIP files were preserved."
  echo "Run $0 --purge to remove /etc/edgewatch and /var/lib/edgewatch too."
fi
