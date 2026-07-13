# EdgeWatch Command Center 0.5.5

EdgeWatch is a self-hosted Ubuntu edge monitoring dashboard for network activity, security posture, service health, WireGuard, Plex, public endpoints, Linode Cloud Firewall state, and ntfy notifications.

The browser application listens only on loopback. Caddy and oauth2-proxy provide the authenticated HTTPS boundary. The privileged collector has no listening socket.

## Release highlight: private site configuration and sanitized source

Version 0.5.5 removes deployment-specific names, domains, public addresses, private topology, Caddy log paths, and retired ports from application source. These values now belong in `/etc/edgewatch/site.toml`, a private overlay that is read on top of the general configuration.

The topology view is configuration-driven. Public connection aliases are scoped and appear only when a matching connection is actually observed. No remote service or media node is permanently listed by JavaScript.

The public distribution uses only generic names, reserved example domains, and documentation networks. A regression test scans the release for known private literals.

The map zoom correction and authenticated Microsoft Entra metadata from 0.5.3 remain included.

## Acknowledged findings

Every active finding now has an **Acknowledge and mute** switch.

Acknowledging a finding:

- keeps the finding active and visible
- keeps its severity and risk score contribution unchanged
- moves it into an **Acknowledged Findings** card above Recent Security Events
- suppresses repeated timeline entries for that fingerprint
- suppresses ntfy alert and recovery messages for that fingerprint
- records who acknowledged it and when
- persists across browsers, restarts, and upgrades

Meaningful lifecycle changes are still recorded. A severity change creates one event. Resolution creates one event and clears the acknowledgement. Resuming alerts creates one event. A future recurrence after resolution alerts normally.

This is designed for intentional exceptions such as SSH password authentication that remains enabled by choice. It does not change the underlying check or represent a waiver of risk.

## Main capabilities

- Live CPU, memory, disk, inode, load, uptime, TCP, and traffic data
- Public, internal, and loopback connection classification
- Local MapLibre and PMTiles connection map with no third-party runtime map calls
- WireGuard peer health and configured aliases
- Plex sessions, users, devices, Direct Play, Direct Stream, and transcode state
- Caddy, systemd, UFW, SSH, AppArmor, NTP, update, reboot, and kernel posture checks
- Public endpoint, TLS certificate, and DNS alignment checks
- Linode Cloud Firewall policy and attachment verification using a read-only token
- ntfy alerting with severity threshold, cooldown, escalation, recovery, and per-finding mute
- Active authenticated dashboard-user roster
- Server-sent events for live dashboard updates
- SQLite history, transfer accounting, alert state, and acknowledgement state
- Immutable releases, pre-upgrade backup, automatic failed-activation rollback, and hardened systemd units

## Security boundary

```text
Internet
   |
   v
Caddy HTTPS :443
   |  strips client-supplied identity headers
   |  forward_auth to oauth2-proxy
   v
oauth2-proxy :4180 on loopback
   |  Microsoft Entra authentication
   |  trusted X-Auth-Request-* headers
   +------------------------------+
   |                              |
   v                              v
EdgeWatch web :8765          User roster :8766
user edgewatch               user edgewatch
read-only monitoring DB      memory-only sessions
write access only to
/var/lib/edgewatch/control

Privileged collector
user root, restricted capabilities, no listening socket
   |
   +-- /run/edgewatch/latest.json
   +-- /var/lib/edgewatch/edgewatch.db
   +-- /var/lib/edgewatch/control/edgewatch-control.db
```

The only application-data mutation exposed by the main web service is the authenticated finding acknowledgement endpoint. All other main API routes remain GET or HEAD only.

## Supported platform

- Ubuntu 22.04 or 24.04
- Python 3.10 or newer
- Existing Caddy reverse proxy
- oauth2-proxy for authenticated identity headers
- Optional WireGuard, Plex, MaxMind GeoLite2, Linode API, and ntfy integrations

## Install or upgrade

First installation or upgrade:

```bash
sha256sum -c edgewatch-0.5.5-install.sha256
tar -xzf edgewatch-0.5.5-install.tar.gz
cd edgewatch-0.5.5
sudo bash scripts/install.sh
```

Existing EdgeWatch 0.5.4 installations can follow [UPGRADE.md](UPGRADE.md). The installer preserves `config.toml`, the private `site.toml` overlay, secrets, databases, acknowledgement state, and the local PMTiles archive.

## Documentation

- [INSTALL.md](INSTALL.md): first installation and reverse-proxy integration
- [UPGRADE.md](UPGRADE.md): exact 0.5.3 to 0.5.5 upgrade procedure
- [CONFIGURATION.md](CONFIGURATION.md): configuration and secrets reference
- [OPERATIONS.md](OPERATIONS.md): status, backup, restore, rollback, and troubleshooting
- [ARCHITECTURE.md](ARCHITECTURE.md): components, data flow, and acknowledgement state machine
- [SECURITY.md](SECURITY.md): threat model, controls, limitations, and review results
- [TEST_REPORT.md](TEST_REPORT.md): automated, integration, visual, and packaging evidence
- [RELEASE_NOTES.md](RELEASE_NOTES.md): release-specific behavior and migration notes
- [CHANGELOG.md](CHANGELOG.md): version history
- [CONTRIBUTING.md](CONTRIBUTING.md): development workflow
- [SUPPORT.md](SUPPORT.md): issue-reporting guidance
- [SANITIZATION.md](SANITIZATION.md): public-package and private-site separation
- [GITHUB_PUBLISHING.md](GITHUB_PUBLISHING.md): repository contents, settings, and release assets
- [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md): bundled library and data notices

## Scope limits

EdgeWatch is not an IDS, EDR agent, SIEM, vulnerability scanner, malware scanner, packet inspection platform, or proof that a host is uncompromised. It reports the state it can observe at each sample interval. Very short connections may begin and end between samples.

## Authoritative implementation references

- Caddy forward authentication: https://caddyserver.com/docs/caddyfile/directives/forward_auth
- oauth2-proxy request headers: https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview/
- OWASP CSRF prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- systemd sandboxing: https://www.freedesktop.org/software/systemd/man/systemd.exec.html
- Python SQLite backup API: https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection.backup
- Plex dashboard bandwidth behavior: https://support.plex.tv/articles/200871837-status-and-dashboard/
- Plex bitrate and buffering behavior: https://support.plex.tv/articles/227715247-server-settings-bandwidth-and-transcoding-limits/
- SQLite journal modes: https://sqlite.org/wal.html
- ntfy publishing: https://docs.ntfy.sh/publish/
- MapLibre clustered GeoJSON custom properties: https://www.maplibre.org/maplibre-gl-js/docs/examples/display-html-clusters-with-custom-properties/
- MapLibre rendered-feature queries: https://maplibre.org/maplibre-gl-js/docs/API/classes/Map/#queryrenderedfeatures
