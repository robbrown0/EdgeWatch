# EdgeWatch 0.5.4 architecture

## Goals

EdgeWatch provides a focused operational and security view of an Ubuntu edge without exposing a privileged management API. It separates collection, read-mostly presentation, narrow operator controls, authentication, and public TLS into distinct components.

## Components

### Privileged collector

`edgewatch-agent.service` runs the Python collector as root with a restricted capability set and systemd sandbox. It has no listening socket.

It gathers:

- Linux resource and network state
- sockets and listeners
- SSH and systemd evidence
- UFW, WireGuard, AppArmor, NTP, update, and kernel posture
- Plex and public endpoint state
- optional Linode, GeoIP, and ntfy integration data

It writes:

```text
/run/edgewatch/latest.json
/var/lib/edgewatch/edgewatch.db
/var/lib/edgewatch/control/edgewatch-control.db
```

The control database is touched by the collector only for acknowledgement reconciliation and lifecycle events.

### Main web service

`edgewatch-web.service` runs as the unprivileged `edgewatch` account on `127.0.0.1:8765`.

It reads the live snapshot and monitoring history. It has write permission only to `/var/lib/edgewatch/control`.

Its API is read-only except for:

```text
POST /api/v1/finding-acknowledgements
```

That endpoint changes only acknowledgement state for an exact current finding fingerprint.

### Monitor-user helper

`edgewatch-monitor-users.service` runs as `edgewatch` on `127.0.0.1:8766`.

It keeps a bounded, memory-only roster based on authenticated browser heartbeats. It does not write a database or expose client IP addresses in its API response. A process restart intentionally clears the roster.


### Configuration layers

`/etc/edgewatch/config.toml` contains general runtime settings. `/etc/edgewatch/site.toml` is a private overlay for environment-specific domains, addresses, aliases, Caddy activity sources, custom port labels, and topology nodes. `/etc/edgewatch/secrets.toml` remains root-only and contains credentials.

The loader merges the site overlay over the general configuration. Lists and repeated tables in the overlay replace the corresponding general values. This keeps the public source distribution generic while preserving a fully customized deployment.

Public connection aliases are applied only to observed active or recent connections. Topology nodes are rendered only from configured `topology_services`; public aliases never create topology nodes automatically.

### Caddy and oauth2-proxy

Caddy owns public TLS and sends authentication checks to oauth2-proxy. Client-supplied identity headers are removed before oauth2-proxy results are copied into upstream requests.

Caddy routes:

```text
/api/v1/monitor-users*  -> 127.0.0.1:8766
all other EdgeWatch     -> 127.0.0.1:8765
```

Both routes remain behind the same authentication check.

The main web service also exposes `GET /api/v1/identity`. It requires a trusted oauth2-proxy identity header and returns only allowlisted display metadata from `[identity]`. Tenant and application IDs are identifiers, not credentials. Client secrets, cookie secrets, tokens, and cookies are never loaded by this endpoint.

## Data flow

```text
Host and service state
        |
        v
Privileged collector
   |            |
   |            +--> ntfy and optional APIs through bounded outbound calls
   v
Live JSON in /run                    SQLite history
   |                                      |
   +------------------+-------------------+
                      v
              Main web service
                      |
              authenticated HTTPS
                      |
                    Browser
                      |
              heartbeat through Caddy
                      v
              Monitor-user helper
```

## Finding identity

Every finding has a stable fingerprint generated from its check identity rather than display position. Acknowledgement is keyed by that fingerprint so similarly titled findings are not muted accidentally.

## Acknowledgement state machine

```text
ACTIVE, UNACKNOWLEDGED
    | operator acknowledges
    v
ACTIVE, ACKNOWLEDGED
    | severity changes          -> remain acknowledged, record one event
    | operator resumes          -> ACTIVE, UNACKNOWLEDGED
    | condition resolves        -> RESOLVED, acknowledgement cleared
    v
RESOLVED
    | condition recurs
    v
ACTIVE, UNACKNOWLEDGED
```

Acknowledgement affects event and notification delivery only. It does not modify the assessment, severity, evidence, recommendation, or risk score.

## Storage design

### Monitoring database

`/var/lib/edgewatch/edgewatch.db` contains bounded history, transfer accounting, security events, and notification state. The collector owns writes. The web service opens it read-only.

### Control database

`/var/lib/edgewatch/control/edgewatch-control.db` contains only acknowledgement rows and acknowledgement lifecycle events. It uses SQLite rollback-journal mode, full synchronization, a busy timeout, and immediate write transactions for small serialized changes.

It is separate so the web process never needs write permission to monitoring history.

### Live snapshot

`/run/edgewatch/latest.json` is atomically replaced and is normally on tmpfs. The snapshot includes the current acknowledgement projection needed by the browser.

## Notification design

Notification state remains in the monitoring database. Before evaluating a finding for a new, escalation, cooldown, or recovery message, the notifier checks the current active acknowledgement fingerprints.

Resuming alerts clears the notification suppression for the finding so the next collector cycle evaluates it normally.

## Performance controls

- Fast and slow collection intervals are separate.
- Persistent history writes are batched.
- Recent-flow memory is time bounded.
- Maintenance and Linode checks are cached.
- External requests and local commands have explicit timeouts and bounded reads.
- Unchanged acknowledgement reconciliation avoids database row updates.
- The active-user roster is memory-only and expires entries after five minutes.
- Map libraries and data are local at runtime.

## Upgrade model

Releases are immutable directories under `/opt/edgewatch/releases`. `/opt/edgewatch/current` is switched atomically. The installer preserves general configuration, private site configuration, and secrets, creates pre-upgrade backups, backs up systemd units, validates health, and restores the prior release and configuration after a failed activation.
