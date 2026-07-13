# EdgeWatch operations guide

## Service overview

```text
edgewatch-agent.service          privileged collector, no listener
edgewatch-web.service            main dashboard on 127.0.0.1:8765
edgewatch-monitor-users.service  memory-only active-user helper on 127.0.0.1:8766
edgewatch-geoip-update.timer     optional weekly GeoIP update
```

## Common commands

```bash
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh status
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh logs
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh restart
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh test
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh collect-once
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh notification-test
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh security
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh snapshot
```

## Local health

```bash
curl -fsS http://127.0.0.1:8765/healthz
curl -fsS http://127.0.0.1:8766/healthz
```

Port 8765 reports degraded status if the live snapshot is missing or stale. Port 8766 reports the monitor-user helper process health.

## Logs

```bash
sudo journalctl -u edgewatch-agent -u edgewatch-web -u edgewatch-monitor-users -f
```

Recent startup failures:

```bash
sudo journalctl -u edgewatch-agent -u edgewatch-web -u edgewatch-monitor-users --since '15 minutes ago' --no-pager
```

## Acknowledged findings

The control state is stored in:

```text
/var/lib/edgewatch/control/edgewatch-control.db
```

Use the dashboard switch rather than editing the database directly.

Expected behavior:

- Acknowledge and mute creates one event.
- The finding remains in the posture assessment.
- Repeated timeline and ntfy messages stop for that fingerprint.
- Resume alerts restores normal evaluation.
- Resolution clears the acknowledgement.

The operations snapshot command reports the current acknowledged count.

## Backup

Create a backup without secrets:

```bash
sudo /opt/edgewatch/current/scripts/backup.sh
```

Choose a destination:

```bash
sudo /opt/edgewatch/current/scripts/backup.sh /mnt/secure-backups
```

Include secrets only when necessary:

```bash
sudo /opt/edgewatch/current/scripts/backup.sh --include-secrets /mnt/secure-backups
```

Backups use SQLite's online backup API so a consistent copy can be taken while the databases are active. Archives are mode 0600. Secret-inclusive archives are not encrypted.

## Restore

For an application rollback, use the immutable release procedure in UPGRADE.md rather than restoring a database backup.

For data recovery:

1. Stop all EdgeWatch services.
2. Extract the backup to a protected temporary directory.
3. Restore `config.toml`, `site.toml`, and, only when appropriate, `secrets.toml` with their required ownership and modes.
4. Restore `edgewatch.db` as `root:edgewatch` mode 0660.
5. Restore `control/edgewatch-control.db` as `edgewatch:edgewatch` mode 0660.
6. Start the services and verify both health endpoints.

Example service stop and start:

```bash
sudo systemctl stop edgewatch-agent edgewatch-web edgewatch-monitor-users
# Restore files here.
sudo systemctl start edgewatch-agent edgewatch-web edgewatch-monitor-users
```

## Release rollback

```bash
ls -ld /opt/edgewatch/releases/*
readlink -f /opt/edgewatch/current
```

Switch the symlink atomically to the prior release and restart services. See UPGRADE.md for exact commands.

## Caddy changes

Always back up and validate the Caddyfile before reload:

```bash
sudo cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak-$(date +%Y%m%d-%H%M%S)
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Never reload after a failed validation.

## Disk use

Persistent growth is bounded by retention and consists mainly of:

- `/var/lib/edgewatch/edgewatch.db`
- `/var/lib/edgewatch/control/edgewatch-control.db`
- Caddy access logs under their roll policy
- immutable application releases, with the installer retaining the newest four
- backups in `/var/backups/edgewatch`
- optional GeoIP and PMTiles assets

Inspect:

```bash
sudo du -h -d 2 /var/lib/edgewatch /var/backups/edgewatch /opt/edgewatch 2>/dev/null | sort -h
```

## Troubleshooting

### Dashboard works locally but not publicly

Check Caddy and oauth2-proxy:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl status caddy oauth2-proxy --no-pager
```

### Acknowledge switch returns an identity error

Confirm oauth2-proxy has `set_xauthrequest = true` and Caddy copies `X-Auth-Request-User`, `X-Auth-Request-Email`, and `X-Auth-Request-Preferred-Username` after stripping client-supplied copies.

### Active users do not appear

```bash
curl -fsS http://127.0.0.1:8766/healthz
sudo systemctl status edgewatch-monitor-users --no-pager
```

Confirm the two monitor-user routes go to port 8766.

### ntfy is configured but no message arrives

```bash
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh notification-test
sudo journalctl -u edgewatch-agent --since '15 minutes ago' --no-pager
```

Check whether the specific finding is acknowledged and muted.

### Map is unavailable

Use the dashboard map asset status or inspect:

```bash
ls -lh /opt/edgewatch/current/edgewatch/static/maps/
```

The application package does not bundle the large PMTiles archive.
