# EdgeWatch 0.5.4 release notes

Release date: 2026-07-13

## Configuration-driven environment metadata

Version 0.5.4 removes environment-specific names, domains, addresses, old ports, and topology labels from application source. EdgeWatch now reads private deployment metadata from `/etc/edgewatch/site.toml`.

The private overlay supports:

- public and private connection aliases with explicit scopes
- Plex server definitions
- public URL checks and expected DNS names
- custom service port labels
- Caddy access-log paths and host classification
- topology service nodes and their health-check relationships
- the public dashboard hostname

Public aliases appear only when a matching connection is actually observed. They do not create permanent topology nodes.

## Generic public distribution

All bundled examples and tests now use reserved example domains, documentation networks, or generic names. Personal attribution, private hostnames, private topology labels, old public ports, and known real public addresses are absent from the public installer.

A distribution sanitization test blocks reintroduction of the known private literals.

## Map route persistence

The offscreen route correction from 0.5.3 remains included. Active routes stay visible to the map edge when a client leaves the current viewport.

## Microsoft Entra account details

The authenticated account drawer continues to display safe tenant, application, and session metadata. Secrets, tokens, and cookies are excluded.

## Upgrade behavior

- Existing `config.toml`, `site.toml`, and `secrets.toml` are preserved.
- The installer creates timestamped backups of both non-secret configuration files.
- A neutral `site.toml` is created only when none exists.
- Failed activation restores the previous release, unit files, and configuration.
- The local PMTiles archive and databases remain preserved.
