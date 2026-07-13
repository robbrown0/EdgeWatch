# EdgeWatch 0.5.4 test report

Build date: 2026-07-13

## Result

The release passed dependency, Python compilation, JavaScript syntax, shell syntax, systemd unit, configuration migration, API, and unit tests. The final suite was also run with a real common-path oauth2-proxy configuration present, matching the live VPS condition that exposed the original environment-dependent test.

The final automated suite ran 60 tests with no failures or errors.

## Fix-specific coverage

### Map route persistence

- Reproduced a zoomed viewport with one visible peer and one peer outside the map bounds.
- Verified `routeInputFeatures` combines rendered cluster or point features with active offscreen peer features.
- Verified `visibleRouteFeatures` still generates the route to the offscreen peer.
- Verified existing cluster route behavior remains covered.
- Parsed `maplibre-edgewatch.js` with Node.js.

### Microsoft Entra account metadata

- Verified the frontend requests `/api/v1/identity` and renders dynamic directory, tenant, application, client ID, access, and session fields.
- Verified the prior misleading `Configured Microsoft Entra tenant` browser text is absent.
- Verified the metadata API rejects requests without a trusted oauth2-proxy identity header.
- Verified the authenticated response receives `Cache-Control: no-store`.
- Verified the response omits client secrets, cookie secrets, tokens, and cookies.
- Verified oauth2-proxy parsing uses a strict allowlist of non-secret configuration keys.
- Verified Microsoft issuer URLs and legacy `azure_tenant` settings can supply a tenant ID.
- Verified cookie durations are rendered as human-readable session lifetime and refresh values.
- Verified migration appends a missing `[identity]` section.
- Verified migration fills blank safe fields in the starter section.
- Verified existing nonblank friendly names and access labels are preserved.
- Verified a second migration is idempotent.


### Private site configuration and sanitization

- Verified `site.toml` is loaded automatically beside `config.toml` and can override environment-specific sections.
- Verified public aliases are applied only to observed active or recent connections and expire with the recent-flow window.
- Verified Caddy activity paths, hosts, kinds, and labels are read from configured sources.
- Verified query strings are removed before activity data reaches the snapshot.
- Verified topology service metadata is carried into the collector snapshot.
- Verified the distributable source contains none of the known private names, domains, addresses, or retired ports.
- Verified the installer preserves, backs up, and restores the private site configuration.

### Installer safety

- Verified configuration is backed up before identity migration.
- Verified failure rollback restores the pre-install configuration.
- Verified a new config is removed if an initial installation fails.
- Verified the protected secrets file remains root-only and unreadable by the `edgewatch` service account.
- Verified the identity discovery helper is installed executable but does not receive or emit secret fields.
- Verified systemd units retain least-privilege controls.

## Recorded result

```text
Ran 60 tests in 2.495s

OK
```

## Complete automated suite

The suite covers:

- collector snapshot and history contracts
- layered general and private-site configuration parsing and risk scoring
- public, internal, recent, and loopback connection classification, including scoped aliases
- acknowledgement persistence, concurrency, lifecycle, and event ordering
- frontend source safety and DOM ID consistency
- MapLibre route and cluster behavior
- remote Plex traffic reconciliation and client drilldowns
- identity metadata discovery, migration, and secret isolation
- configuration-driven Caddy activity and topology metadata
- distribution sanitization against known private literals
- Linode firewall attachment verification
- ntfy alert, mute, recovery, and resume behavior
- monitor-user roster bounds and browser classification
- Linux network, process, SSH, memory, CPU, and WireGuard parsers
- Plex Direct Play and transcode parsing
- SQLite atomic writes, journal compatibility, and traffic accounting
- authenticated finding controls and request guards

## Static and dependency checks

Passed:

- `pip check` against the pinned dependency set
- Python bytecode compilation for application, tests, and identity discovery helper
- `node --check` for `app.js`
- `node --check` for `maplibre-edgewatch.js`
- `bash -n` for every shell script
- `scripts/verify-units.sh`
- internal package manifest validation after archive extraction

## Security review notes

The browser receives tenant and application identifiers only after an authenticated request. These identifiers are not credentials. The release does not read or return oauth2-proxy client secrets, cookie secrets, access tokens, ID tokens, refresh tokens, or session cookies.

The installer can inspect oauth2-proxy configuration as root because the relevant files may be protected. It extracts only allowlisted non-secret keys and writes only safe display metadata into `/etc/edgewatch/config.toml`.

## Remaining live acceptance checks

The build environment cannot reproduce a live Caddy, oauth2-proxy, systemd, PMTiles, Entra, and private site configuration. After installation on the VPS, verify:

1. `/healthz` reports version `0.5.4`.
2. All three EdgeWatch services are active.
3. Zooming the map keeps routes visible to offscreen active clients.
4. The signed-in account drawer shows the discovered tenant ID, application client ID, and session timing.
5. Friendly directory and application labels are correct.
6. No secret value appears in the drawer or `/api/v1/identity`.
7. Configured topology nodes and public aliases match the private site file.
