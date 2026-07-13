#!/usr/bin/env bash
set -Eeuo pipefail

CURRENT="/opt/edgewatch/current"
CONFIG="/etc/edgewatch/config.toml"
command_name="${1:-status}"

case "$command_name" in
  status)
    systemctl --no-pager --full status edgewatch-agent.service edgewatch-web.service edgewatch-monitor-users.service
    printf '\nLocal health:\n'
    curl --fail --silent --show-error http://127.0.0.1:8765/healthz
    printf '\n'
    ;;
  logs)
    journalctl -u edgewatch-agent.service -u edgewatch-web.service -u edgewatch-monitor-users.service -f
    ;;
  restart)
    systemctl restart edgewatch-agent.service edgewatch-web.service edgewatch-monitor-users.service
    systemctl --no-pager --full status edgewatch-agent.service edgewatch-web.service edgewatch-monitor-users.service
    ;;
  test)
    cd "$CURRENT"
    PYTHONPATH=. venv/bin/python -m compileall -q edgewatch tests
    PYTHONPATH=. venv/bin/python -m unittest discover -s tests -v
    venv/bin/python -m pip check
    for script in scripts/*.sh; do bash -n "$script"; done
    curl --fail --silent --show-error http://127.0.0.1:8765/healthz
    printf '\n'
    ;;
  collect-once)
    cd "$CURRENT"
    PYTHONPATH=. venv/bin/python -m edgewatch.agent --config "$CONFIG" --once
    ;;
  notification-test)
    cd "$CURRENT"
    PYTHONPATH=. venv/bin/python -m edgewatch.agent --config "$CONFIG" --test-notification
    ;;
  geoip-update)
    systemctl start edgewatch-geoip-update.service
    systemctl --no-pager --full status edgewatch-geoip-update.service
    systemctl restart edgewatch-agent.service
    ;;
  security)
    systemd-analyze security edgewatch-agent.service edgewatch-web.service edgewatch-monitor-users.service --no-pager
    ;;
  snapshot)
    "$CURRENT/venv/bin/python" - <<'PY'
import json
from pathlib import Path
path = Path('/run/edgewatch/latest.json')
with path.open() as handle:
    data = json.load(handle)
print(json.dumps({
    'generated_at': data.get('generated_at'),
    'risk': data.get('posture', {}).get('risk_score'),
    'risk_level': data.get('posture', {}).get('risk_level'),
    'streams': data.get('plex', {}).get('active_streams'),
    'public_peers': data.get('network', {}).get('connections', {}).get('public_peer_count'),
    'findings': data.get('posture', {}).get('active_findings'),
    'acknowledged_findings': data.get('posture', {}).get('acknowledged_findings', 0),
}, indent=2))
PY
    ;;
  *)
    echo "Usage: $0 {status|logs|restart|test|collect-once|notification-test|geoip-update|security|snapshot}" >&2
    exit 2
    ;;
esac
