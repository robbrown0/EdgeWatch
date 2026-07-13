# Upgrade EdgeWatch 0.5.4 to 0.5.5

Version 0.5.5 adds conservative Plex connection identity correlation and the related dashboard context.  It retains all 0.5.4 configuration, map, traffic, identity, and rollback behavior.

## Verify and extract

```bash
cd "$HOME"
sha256sum -c edgewatch-0.5.5-install.sha256
tar -xzf edgewatch-0.5.5-install.tar.gz
cd edgewatch-0.5.5
sha256sum -c MANIFEST.sha256
```

## Back up and install

```bash
sudo /opt/edgewatch/current/scripts/backup.sh
sudo bash scripts/install.sh
```

The installer preserves and backs up `/etc/edgewatch/config.toml` and `/etc/edgewatch/site.toml`, preserves secrets and application data, runs the full test suite, and activates an immutable release only after validation succeeds.

## Validate

```bash
readlink -f /opt/edgewatch/current
cat /opt/edgewatch/current/VERSION
systemctl is-active edgewatch-agent edgewatch-web edgewatch-monitor-users
curl -fsS http://127.0.0.1:8765/healthz && echo
curl -fsS http://127.0.0.1:8766/healthz && echo
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh test
```

Expected health output includes:

```json
{"status":"ok","version":"0.5.5"}
```

## Acceptance checks

1. Confirm the dashboard and live updates remain healthy.
2. Confirm map routes remain visible when endpoints leave the viewport.
3. Start one remote Plex stream and open its remote connection details.
4. When Caddy and Plex expose the same unique client identifier, confirm the drawer shows a confirmed Plex account and device.
5. Confirm unmatched or ambiguous identifiers do not claim an account identity.
6. Confirm account, topology, acknowledgement, and notification behavior remains intact.
