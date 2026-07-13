# Changelog

## 0.5.5 - 2026-07-13

- Added exact Plex client identifier correlation for conservative connection profiles.
- Added safe Plex user, client, playback, and playback-session identifiers to session snapshots.
- Added confirmed account context and evidence to remote connection UI.
- Added ambiguity safeguards so labels, usernames, and IP addresses alone never establish identity.
- Added Node.js to installer prerequisites for frontend behavior tests.
- Retained the 0.5.4 map route persistence, traffic reconciliation, private site overlay, and rollback fixes.

All notable EdgeWatch changes are documented here.

## 0.5.5 - 2026-07-13

### Added

- Private `/etc/edgewatch/site.toml` overlay for deployment-specific domains, addresses, aliases, topology, Caddy activity sources, and custom port labels
- Scoped public, private, and WireGuard aliases
- Configuration-driven topology service nodes
- Distribution sanitization regression test
- Installer preservation, backup, rollback, and examples for the private site configuration

### Changed

- Caddy activity classification now reads log paths, hostnames, kinds, and labels from configuration
- Public peer display names now come from configured aliases in the collector snapshot
- Topology rendering now uses `snapshot.topology.services` instead of fixed application names and addresses
- Public examples and tests now use generic names, reserved domains, and documentation networks

### Removed

- Hardcoded deployment domains, public addresses, private topology names, Caddy log sources, and retired Plex ports
- Personal attribution and personal test identity data from the distributable package

### Fixed

- Known remote services appearing as permanent source-code concepts rather than only when a matching connection is observed

## 0.5.3 - 2026-07-13

### Added

- Authenticated `/api/v1/identity` endpoint containing only safe display metadata
- Installer discovery of non-secret tenant, application, and session settings from oauth2-proxy
- Configuration migration with rollback-safe backup and preservation of existing nonblank identity labels
- Behavioral tests for offscreen routes and identity metadata isolation

### Changed

- Signed-in account details now use dynamic configuration instead of misleading generic browser text
- Account drawer can show the Microsoft Entra tenant ID, application client ID, directory label, and session timing

### Fixed

- Active route lines disappearing when their client endpoint moved outside the current map viewport
- Missing useful Entra application and tenant details in the signed-in account drawer

## 0.5.2 - 2026-07-12

### Added

- Clickable Active Streams and Streaming Activity Streams cards with a full Plex client roster
- Clickable Remote Clients and Remote Streams cards with filtered client rosters
- Remote-session representation during short socket-sampling gaps caused by buffered playback
- Flow context showing remote-through-VPS and local-home-network Plex client counts
- 30-second rolling VPS egress average for traffic comparison

### Changed

- Plex traffic comparison now includes only remote sessions and separates paused remote sessions
- Flow panel title now explicitly describes connections to the VPS
- Security evidence fields stack labels above values for reliable tablet rendering

### Fixed

- Local Plex sessions inflating the remote Plex bandwidth comparison
- Active remote Plex sessions disappearing from the client view during a momentary TCP sampling gap
- Ambiguity between all Plex streams and connections visible on the VPS
- Long security evidence labels overlapping their values

## 0.5.1 - 2026-07-12

### Changed

- Connection routes are generated from currently rendered MapLibre cluster or client markers
- Cluster routes aggregate connection count, active state, and direction
- Routes recalculate after clustered data updates and map movement
- Installer activation explicitly restarts all EdgeWatch services
- Installer health verification requires the newly installed version

### Fixed

- Dashed routes that appeared to stop short when their endpoint clients were hidden inside a cluster
- Upgrades that could leave already-running processes on the prior release after the symlink changed

## 0.5.0 - 2026-07-12

### Added

- Per-finding Acknowledge and mute switch for every active finding
- Acknowledged Findings card above Recent Security Events
- Persistent acknowledgement actor, time, severity, category, and lifecycle state
- Dedicated control database and acknowledgement event timeline
- Resume alerts behavior and automatic acknowledgement clearing on resolution
- Separate loopback-only active monitor-user service
- GitHub workflow, issue templates, contribution guide, support guide, security policy, release checklist, and proprietary license

### Changed

- Muted findings retain severity and posture score contribution
- Repeated events and ntfy messages are suppressed only for the acknowledged fingerprint
- Trusted identity is accepted only from oauth2-proxy `X-Auth-Request-*` headers
- Caddy example strips client-supplied identity headers and routes monitor-user paths to port 8766
- Web systemd unit can write only to the control directory
- Backup uses SQLite online backup for both databases
- Installer backs up and restores systemd units during failed activation rollback
- Long dashboard content wraps cleanly on desktop and mobile
- Unchanged acknowledgement reconciliation avoids unnecessary row writes

### Fixed

- Hardcoded sign-out and tenant-specific browser values
- Missing map zoom target
- Cards that could overflow with long endpoint, listener, service, event, or finding data

## 0.4.0 - 2026-07-12

- Added local MapLibre GL JS rendering with a local PMTiles basemap
- Added map asset installation and validation controls
- Improved dashboard map interaction and visual layout

## 0.3.1 - 2026-07-11

- Corrected WireGuard keepalive parsing
- Corrected TLS certificate compatibility behavior
- Improved connection classification, recent flows, topology, and local map context

## 0.3.0 - 2026-07-11

- Initial packaged EdgeWatch command-center release
