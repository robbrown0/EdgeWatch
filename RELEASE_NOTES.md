# EdgeWatch 0.5.5 release notes

Release date: 2026-07-13

## Connection identity foundation

EdgeWatch now correlates recent Plex requests observed by Caddy with active Plex sessions using the stable Plex client identifier.  A connection is marked confirmed only when one request identifier matches exactly one active session.  IP addresses, usernames, and device labels alone never establish identity.

Confirmed profiles may include:

- authenticated Plex account name and account identifier
- Plex player or device name
- stable client identifier
- the evidence used to make the match

Ambiguous, duplicate, missing, and unmatched identifiers remain explicitly unknown.

## Plex session metadata

The collector now retains safe Plex session identifiers required for correlation:

- `Player.machineIdentifier`
- `Player.playbackId`
- `Player.playbackSessionId`
- Plex user identifier

Tokens, cookies, and credentials are not added to snapshots.

## Dashboard enhancements

Remote connection cards and the connection detail drawer now surface confirmed Plex account context.  The drawer distinguishes confirmed identity from an observed but unmatched client identifier and explains why no account is asserted when evidence is insufficient.

## Installer and validation

The installer now includes Node.js because frontend behavior tests execute JavaScript during pre-activation validation.  The release carries the prior map route persistence correction, remote Plex traffic reconciliation, Entra metadata display, private site overlay, and rollback behavior from 0.5.4.

## Upgrade behavior

The installer preserves and backs up existing configuration, private site metadata, secrets, databases, acknowledgement state, and the local PMTiles archive.  Activation failures restore the previous release and service configuration.
