# EdgeWatch 0.5.4 security review

## Assessment

EdgeWatch provides useful defense and operations visibility for a specific Ubuntu edge. It combines exposure, identity, firewall, availability, certificate, tunnel, host health, connection, and application signals.

It is not proof of host integrity and does not replace an IDS, EDR platform, SIEM, malware scanner, vulnerability scanner, external attack-surface scanner, or independent backup service.

## Protected assets

- VPS and service configuration
- network topology and observed remote addresses
- SSH activity
- Plex session information
- monitoring integrity and history
- Linode, Plex, ntfy, and oauth2-proxy secrets
- authenticated operator identity
- acknowledgement state

## Public boundary

- Uvicorn binds only to `127.0.0.1:8765`.
- The monitor-user helper binds only to `127.0.0.1:8766`.
- oauth2-proxy binds only to loopback.
- Caddy owns public HTTPS and authentication.
- Ports 8765, 8766, and 4180 must not be opened in UFW or the Linode Cloud Firewall.
- TrustedHostMiddleware enforces the configured host allowlist.

## Authentication header trust

The acknowledgement endpoint and active-user helper accept identity only from oauth2-proxy `X-Auth-Request-*` headers.

The supplied Caddy pattern removes client-supplied copies before `forward_auth`, then copies authenticated values from oauth2-proxy. Generic `X-Forwarded-Email`, `X-Forwarded-User`, and `Remote-User` are removed and are not accepted as application identity.

A spoofed identity header sent directly to the public hostname is therefore discarded at the proxy boundary.

## State-changing request protection

The main service exposes one mutation:

```text
POST /api/v1/finding-acknowledgements
```

Controls include:

- authenticated identity required
- exact HTTPS Origin host required
- `application/json` required
- custom `X-EdgeWatch-Action` header required
- 4096-byte body limit
- strict request model with unknown fields rejected
- fingerprint length and character validation
- acknowledgement allowed only for a finding present in the current live snapshot
- database work moved off the asynchronous event loop

Other non-GET and non-HEAD requests to the main service are rejected.

## Identity metadata isolation

`GET /api/v1/identity` requires a trusted oauth2-proxy identity header. Its response is generated from a fixed allowlist of display fields. The installer reads only non-secret oauth2-proxy settings needed for the account drawer, such as issuer, tenant ID, client ID, and cookie timing. It ignores client secrets, cookie secrets, tokens, and session cookies.

The configuration backup is restored automatically if installation fails after identity migration. Existing nonblank identity labels are not overwritten.

## Least privilege

### Collector

- Runs as root only because host, firewall, WireGuard, and journal evidence requires elevated access.
- Has no listener.
- Uses fixed command arrays without shell execution.
- Uses a restricted capability set and systemd sandbox.
- Writes only under the configured runtime and data directories.

### Main web service

- Runs as `edgewatch`.
- Reads snapshot, history, configuration, and static files.
- Cannot read `/etc/edgewatch/secrets.toml`.
- Can write only `/var/lib/edgewatch/control`.
- Has no command, configuration, upload, remediation, or arbitrary file API.

### Monitor-user helper

- Runs as `edgewatch`.
- Keeps only a memory roster.
- Returns identity, device class, browser class, and timestamps, but not client addresses.
- Is reachable only through loopback or the authenticated Caddy route.

## Browser security

- Content Security Policy allows local scripts, styles, images, workers, and connections only.
- Framing is denied.
- MIME sniffing is disabled.
- Referrer information is suppressed.
- Browser permissions such as camera, microphone, and geolocation are denied.
- Observed data is rendered with text nodes rather than HTML insertion.
- No analytics, CDN, remote font, or live third-party map request is used.

## Private site configuration

`/etc/edgewatch/site.toml` contains no credentials, but it can reveal domains, addresses, aliases, and topology. Keep it root-owned, readable only by the `edgewatch` group, and out of public repositories.

## Secrets

`/etc/edgewatch/secrets.toml` is expected to be `root:root` mode 0600. The web service account must not be able to read it.

Secrets are not copied into browser snapshots. Backups omit them unless `--include-secrets` is explicitly requested. Secret-inclusive backups are unencrypted and require external protection.

## Storage and integrity

- Live JSON is atomically replaced.
- Monitoring and control databases use SQLite rollback-journal mode and full synchronization.
- Write transactions are short and control writes use `BEGIN IMMEDIATE` for serialization.
- Monitoring history remains read-only to the web service.
- Backup uses SQLite's online backup API.
- Retention is bounded.
- Finding and notification state uses stable fingerprints.
- Concurrent acknowledgement requests are idempotent and create one event.

Rollback-journal mode was selected for the small control store to avoid relying on WAL behavior and its additional shared-memory files. This is a conservative choice for a low-write control database.

## Integration controls

- Plex calls use only configured URLs and bounded responses.
- Linode checks use GET requests and should use a read-only token.
- ntfy uses outbound publishing and supports bearer authentication.
- GeoIP lookup is local so observed addresses are not sent to a lookup API.
- Every local command and external request has an explicit timeout.

## Dependency review

- Runtime dependencies are exactly pinned in `requirements.lock`.
- `pip check`, Ruff, Bandit, compilation, and the full unit suite are required before packaging.
- Starlette is pinned at 1.3.1, the patched release for its multipart form parsing advisory. EdgeWatch does not expose a form-upload route.
- The online advisory feed could not be queried from the final isolated build because outbound DNS resolution failed. The live command is documented in TEST_REPORT.md.

## Security coverage

Strong coverage includes:

- public listeners and unexpected ports
- UFW and optional Linode Cloud Firewall state
- SSH password, root, key, and authentication settings
- recent SSH successes and failures
- public and internal TCP connection context
- WireGuard peer freshness and topology
- TLS expiry and endpoint reachability
- DNS alignment
- expected and failed systemd services
- warning-level service journal activity
- package updates, reboot need, unattended updates, AppArmor, NTP, and network sysctls
- capacity, interface errors, drops, and connection count
- Plex availability and stream behavior
- persistent findings, ntfy lifecycle, and per-finding acknowledgement

## Limitations

- No packet payload inspection
- No signature-based network detection
- No file integrity monitoring
- No rootkit or malware scan
- No operating-system vulnerability database scan
- No external Internet scanner
- No automatic IP reputation labels
- No automated firewall block, service restart, or configuration remediation
- Sample-based collection can miss very short connections
- A local process able to reach loopback could submit a cosmetic monitor-user heartbeat, although it cannot reach the public service without host access and it gains no privilege from doing so

## Recommended operating policy

- Keep all application ports loopback-only.
- Keep Caddy and oauth2-proxy authentication in front of every route.
- Restrict SSH at the cloud firewall to trusted sources where practical.
- Use read-only Linode credentials.
- Treat a private ntfy topic like a secret or use authenticated ntfy access.
- Review findings before acknowledging them.
- Keep Ubuntu, Caddy, oauth2-proxy, Python dependencies, and GeoIP data current.
- Retain provider snapshots independently of EdgeWatch backups.
- Run `systemd-analyze security` on the live VPS after installation.
