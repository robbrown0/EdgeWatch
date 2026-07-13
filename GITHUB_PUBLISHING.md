# GitHub publishing guide

## Commit to the repository

Commit the application source and public project files:

```text
.github/                 CI, Dependabot, issue forms, and pull request template
deploy/                  Generic configuration and hardened service examples
docs/                    Feature and operational documentation
edgewatch/                Python application and browser frontend
licenses/                 Third-party license texts
scripts/                  Install, backup, operations, GeoIP, and uninstall tools
tests/                    Unit, integration, frontend, security, and sanitization tests
ARCHITECTURE.md           Component and data-flow design
CHANGELOG.md              Version history
CONFIGURATION.md          General, private-site, and secrets reference
CONTRIBUTING.md           Development workflow
GITHUB_PUBLISHING.md      Publication checklist
INSTALL.md                First-install procedure
LICENSE                   Project license
OPERATIONS.md             Status, backup, rollback, and troubleshooting
README.md                 Repository landing page
RELEASE_CHECKLIST.md      Repeatable release process
RELEASE_NOTES.md          Current release details
SANITIZATION.md           Public and private configuration separation
SECURITY.md               Technical security design
SECURITY_POLICY.md        Vulnerability reporting policy
SUPPORT.md                Safe support guidance
TEST_REPORT.md            Release validation evidence
THIRD_PARTY_NOTICES.md    Bundled component notices
UPGRADE.md                Upgrade procedure
VERSION                   Current version
pyproject.toml            Python project metadata
requirements.lock         Exact runtime dependency versions
```

## Do not commit

Do not commit:

```text
/etc/edgewatch/config.toml
/etc/edgewatch/site.toml
/etc/edgewatch/secrets.toml
edgewatch-site-*.toml
production Caddy or oauth2-proxy configuration
production screenshots or snapshots
*.db, *.sqlite*, *.log, *.pmtiles
backup archives
installer build inputs
release tarballs inside the source tree
```

The repository `.gitignore` covers the normal local forms of these files.

## Pre-publish validation

Run:

```bash
python -m unittest discover -s tests -v
python -m compileall -q edgewatch tests scripts/discover-identity.py
node --check edgewatch/static/app.js
node --check edgewatch/static/maplibre-edgewatch.js
for script in scripts/*.sh; do bash -n "$script"; done
bash scripts/verify-units.sh
```

The distribution sanitization test must pass before the repository is made public.

## Repository settings

Recommended settings:

- Protect `main` and require pull requests
- Require the CI workflow before merging
- Enable Dependabot alerts and updates
- Enable secret scanning and push protection
- Enable private vulnerability reporting
- Disable force pushes and branch deletion on `main`
- Keep GitHub Actions permissions read-only unless a workflow needs more

## Release assets

Attach release archives to a GitHub Release rather than committing them to the source branch:

```text
edgewatch-0.5.5-install.tar.gz
edgewatch-0.5.5-install.sha256
```

Never attach the private site overlay or private audit report.
