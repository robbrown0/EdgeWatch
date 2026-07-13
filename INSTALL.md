# EdgeWatch 0.5.4 installation guide

This guide covers a first installation on Ubuntu 22.04 or 24.04. Existing 0.5.3 systems should use [UPGRADE.md](UPGRADE.md).

## 1. Verify and extract the package

Place these files in the same directory:

```text
edgewatch-0.5.4-install.tar.gz
edgewatch-0.5.4-install.sha256
```

Verify the archive:

```bash
sha256sum -c edgewatch-0.5.4-install.sha256
```

Extract it:

```bash
tar -xzf edgewatch-0.5.4-install.tar.gz
cd edgewatch-0.5.4
```

Optional internal manifest verification:

```bash
sha256sum -c MANIFEST.sha256
```

## 2. Review configuration templates

Review:

```bash
less deploy/config.toml
less deploy/site.toml.example
less deploy/secrets.toml.example
```

Important starter values include:

- loopback web listener `127.0.0.1:8765`
- active monitor-user service `127.0.0.1:8766`
- primary public interface
- expected systemd services
- WireGuard interfaces
- allowed public TCP and UDP listener ports
- a private site overlay path
- safe identity display metadata

Environment-specific values belong in `/etc/edgewatch/site.toml`, including:

- public hostnames and URL checks
- public and private connection aliases
- Plex server addresses
- Caddy activity log paths and host classifications
- topology service nodes
- custom service port labels
- optional Linode, GeoIP, and ntfy settings

Do not add real secrets to the extracted release directory.

## 3. Run the installer

```bash
sudo bash scripts/install.sh
```

The installer:

1. installs required Ubuntu packages
2. creates the `edgewatch` service account and protected directories
3. copies the release to `/opt/edgewatch/releases/<version>-<timestamp>`
4. creates an isolated virtual environment and installs exact dependencies
5. runs compilation, unit, shell, dependency, and unit-file checks
6. installs or preserves general configuration, private site configuration, and secrets
7. backs up both non-secret configuration files and discovers safe oauth2-proxy identity metadata
8. initializes the control database
9. installs hardened systemd units
10. activates the immutable release through `/opt/edgewatch/current`
11. waits for the dashboard and monitor-user health endpoints
12. automatically restores the prior release, configuration, and unit files if activation fails

## 4. Configure EdgeWatch

Edit the general non-secret configuration:

```bash
sudo nano /etc/edgewatch/config.toml
```

Create the private environment overlay from the example:

```bash
sudo cp /etc/edgewatch/site.toml.0.5.4.example /etc/edgewatch/site.toml
sudo chown root:edgewatch /etc/edgewatch/site.toml
sudo chmod 0640 /etc/edgewatch/site.toml
sudo nano /etc/edgewatch/site.toml
```

Keep the live site file out of Git. It contains no credentials, but it can reveal domains, addresses, aliases, and topology.

Edit secrets separately:

```bash
sudo nano /etc/edgewatch/secrets.toml
sudo chown root:root /etc/edgewatch/secrets.toml
sudo chmod 600 /etc/edgewatch/secrets.toml
```

Validate and restart:

```bash
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh test
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh restart
```

The installer adds or fills `[identity]` using non-secret oauth2-proxy values when available. Review the result and optionally add friendly names:

```bash
sudo sed -n '/^\[identity\]/,/^\[/p' /etc/edgewatch/config.toml
```

Tenant ID and application client ID are identifiers. Do not put any client secret, cookie secret, token, or cookie value in `[identity]`.

The `edgewatch` account must not be able to read the secrets file:

```bash
sudo -u edgewatch test ! -r /etc/edgewatch/secrets.toml && echo protected
```

## 5. Configure Caddy and oauth2-proxy

EdgeWatch must remain behind authenticated HTTPS. Do not expose ports 8765, 8766, or 4180 through UFW or a cloud firewall.

Use `deploy/oauth2-proxy.cfg.example` as a reference. The important identity setting is:

```text
set_xauthrequest = true
```

Merge the pattern in `deploy/Caddyfile.example` into the existing EdgeWatch site block. It performs three important jobs:

1. removes client-supplied identity headers
2. runs oauth2-proxy `forward_auth` and copies trusted identity headers
3. routes only monitor-user endpoints to port 8766 while the dashboard remains on port 8765

Do not create a second site block for the same hostname.

Before reloading Caddy:

```bash
sudo caddy validate --config /etc/caddy/Caddyfile
```

After a valid result:

```bash
sudo systemctl reload caddy
sudo systemctl is-active caddy
```

## 6. Optional local map archive

The large PMTiles archive is intentionally not bundled in the application release. During an upgrade, the installer preserves an existing archive from the active release by using a hard link when possible and a copy fallback otherwise. For a new installation, follow the map asset procedure in the current project documentation or install the expected file at:

```text
/opt/edgewatch/current/edgewatch/static/maps/edgewatch.pmtiles
```

The dashboard health view reports when required local map assets are missing.

## 7. Verify the services

```bash
sudo systemctl status edgewatch-agent edgewatch-web edgewatch-monitor-users --no-pager
curl -fsS http://127.0.0.1:8765/healthz
curl -fsS http://127.0.0.1:8766/healthz
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh snapshot
```

Then open the authenticated public URL and verify:

- the dashboard loads
- live updates continue
- security findings open correctly
- Acknowledge and mute works for a test finding
- the finding appears in Acknowledged Findings
- Resume alerts works
- active monitor users appear

## 8. Notification test

After ntfy is configured:

```bash
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh notification-test
```

## 9. Back up

```bash
sudo /opt/edgewatch/current/scripts/backup.sh
```

Backups omit secrets unless `--include-secrets` is explicitly supplied. Archives containing secrets are unencrypted and must be protected accordingly.
