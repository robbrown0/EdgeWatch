# EdgeWatch release checklist

## Code and behavior

- [ ] Version updated in VERSION, package metadata, application health, and release notes
- [ ] New behavior has automated tests
- [ ] Existing monitoring, notification, and history behavior remains covered
- [ ] Long values fit desktop and mobile cards
- [ ] Acknowledged findings preserve severity and risk contribution
- [ ] No unbounded in-memory or persistent data path was added

## Security

- [ ] No secrets, tokens, cookies, private topics, or live database files are present
- [ ] Caddy strips identity headers before `forward_auth`
- [ ] State-changing routes are narrow and protected
- [ ] systemd units pass syntax verification
- [ ] `pip check`, Ruff, and Bandit pass
- [ ] Online dependency advisory scan was run or its limitation is documented

## Packaging

- [ ] Virtual environments, caches, logs, databases, screenshots, and PMTiles archives are excluded
- [ ] Internal `MANIFEST.sha256` verifies after extraction
- [ ] TAR.GZ and ZIP contain the same repository files
- [ ] Unit, compile, JavaScript, shell, and unit-file checks pass from an extracted package
- [ ] External archive checksums verify

## Live acceptance

- [ ] Pre-upgrade backup exists
- [ ] Caddy validates before reload
- [ ] All three EdgeWatch services are active
- [ ] Both loopback health endpoints respond
- [ ] Dashboard works through authenticated HTTPS
- [ ] Acknowledge, resume, resolution, and recurrence behavior was exercised
- [ ] ntfy sends for unmuted findings and stays silent for muted findings
- [ ] Rollback procedure was reviewed
