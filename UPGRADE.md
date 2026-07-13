# Upgrade EdgeWatch 0.5.3 to 0.5.4

Version 0.5.4 moves environment-specific domains, addresses, aliases, Caddy activity sources, and topology nodes into a private site configuration file. It retains the map zoom correction and Entra metadata work from 0.5.3.

## Verify and extract

```bash
cd "$HOME"
sha256sum -c edgewatch-0.5.4-install.sha256
tar -xzf edgewatch-0.5.4-install.tar.gz
cd edgewatch-0.5.4
sha256sum -c MANIFEST.sha256
```

## Install the private site overlay

Keep the site file outside GitHub. On an existing EdgeWatch server:

```bash
sudo install -o root -g edgewatch -m 0640 \
  "$HOME/edgewatch-site.toml" \
  /etc/edgewatch/site.toml
```

The file contains no credentials, but it can reveal private infrastructure names, domains, and addresses.

## Back up and install

```bash
sudo /opt/edgewatch/current/scripts/backup.sh
sudo bash scripts/install.sh
```

The installer preserves and backs up both `/etc/edgewatch/config.toml` and `/etc/edgewatch/site.toml`, then runs the full test suite before activation.

## Validate

```bash
readlink -f /opt/edgewatch/current
cat /opt/edgewatch/current/VERSION
systemctl is-active edgewatch-agent edgewatch-web edgewatch-monitor-users
curl -fsS http://127.0.0.1:8765/healthz && echo
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh test
```

Expected health output includes:

```json
{"status":"ok","version":"0.5.4"}
```

## Acceptance checks

1. Confirm the account drawer still shows the expected Entra metadata.
2. Confirm map routes remain visible when endpoints leave the viewport.
3. Confirm configured topology nodes use the names and addresses from `site.toml`.
4. Confirm a configured public alias appears only while that address has an active or recent connection.
5. Confirm Caddy activity is classified using the configured log source and hostname.
