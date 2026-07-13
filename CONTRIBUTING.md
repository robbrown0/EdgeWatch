# Contributing to EdgeWatch

EdgeWatch is currently maintained as a private project. Contributions are accepted only with the project owner's approval.

## Before making a change

1. Open an issue that describes the problem, expected behavior, security impact, and operational impact.
2. Avoid including live IP addresses, account identifiers, tokens, cookies, secrets, private topic names, or production database content.
3. For a behavior change, include an acceptance test plan before implementation.

## Development setup

Use Python 3.10 or newer:

```bash
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.lock
```

Run the required checks:

```bash
PYTHONWARNINGS='error::ResourceWarning' PYTHONPATH=. .venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m compileall -q edgewatch tests
node --check edgewatch/static/app.js
for file in scripts/*.sh; do bash -n "$file"; done
.venv/bin/python -m pip check
```

Optional developer checks:

```bash
.venv/bin/pip install ruff bandit pip-audit
.venv/bin/ruff check edgewatch tests
.venv/bin/bandit -q -r edgewatch
.venv/bin/pip-audit -r requirements.lock
```

The advisory check requires outbound DNS and HTTPS access.

## Design rules

- Keep the collector and browser service privilege boundaries separate.
- Do not expose EdgeWatch loopback ports to the Internet.
- Treat oauth2-proxy identity headers as trusted only after Caddy strips client-supplied copies and `forward_auth` repopulates them.
- Keep state-changing API routes narrow, authenticated, origin checked, content-type checked, and body-size bounded.
- Do not weaken finding severity or risk scoring when a finding is acknowledged.
- Keep secrets outside application releases and out of logs, snapshots, screenshots, tests, and issue reports.
- Prefer bounded data structures, explicit timeouts, and batched persistent writes.
- Use text nodes instead of HTML insertion for untrusted dashboard data.
- Verify desktop and mobile layouts with long field values before release.

## Pull requests

A pull request should include:

- a concise problem statement
- implementation notes
- tests for new and changed behavior
- security and rollback considerations
- documentation updates
- screenshots for visible UI changes
- confirmation that the release package contains no secrets or runtime databases

A change is not ready to merge until the complete test suite passes and the extracted release package has been tested, not only the working directory.
