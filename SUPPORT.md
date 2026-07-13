# EdgeWatch support

## Before opening an issue

Review:

- INSTALL.md for first installation
- UPGRADE.md for release upgrades
- OPERATIONS.md for service, backup, restore, and troubleshooting commands
- CONFIGURATION.md for settings and secret placement
- SECURITY.md for trust boundaries and limitations

Run the local diagnostics:

```bash
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh test
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh status
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh snapshot
sudo /opt/edgewatch/current/scripts/edgewatch-ctl.sh security
```

## What to include

Provide:

- EdgeWatch version
- Ubuntu version
- exact command and sanitized output
- affected service name
- expected and actual behavior
- whether the issue began after an upgrade or configuration change
- relevant timestamps and timezone

## Never include

Do not post:

- `/etc/edgewatch/secrets.toml`
- Plex tokens
- Linode API tokens
- ntfy private topics or credentials
- oauth2-proxy client secrets, cookie secrets, or session cookies
- Microsoft Entra tenant or application secrets
- complete public IP inventories
- unredacted logs containing email addresses or client addresses
- production database files

## Security reports

Do not open a public issue for a suspected vulnerability. Follow SECURITY_POLICY.md.
