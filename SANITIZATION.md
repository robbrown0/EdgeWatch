# Distribution sanitization

EdgeWatch separates public source from private deployment metadata.

The public distribution contains only generic names, reserved example domains, documentation networks, loopback addresses, and product documentation links. It does not contain a live site configuration, credentials, tokens, private keys, databases, logs, PMTiles archives, production snapshots, or production screenshots.

Environment-specific values belong in `/etc/edgewatch/site.toml`, which is intentionally ignored by Git. The public `deploy/site.toml.example` contains fictional documentation values only.

The automated suite includes a distribution scan that blocks known private names, domains, addresses, home paths, and retired ports from reappearing in the package.

Before publishing a release:

```bash
python -m unittest tests.test_distribution_sanitization -v
```

Also inspect the generated archive rather than only the source directory. Release tooling should exclude private site files, secrets, databases, logs, build inputs, and screenshots.
