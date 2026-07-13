# EdgeWatch 0.5.5 test report

Validation date: 2026-07-13

## Automated results

- Python compilation: passed
- JavaScript syntax checks: passed for `app.js` and `maplibre-edgewatch.js`
- Python unit and integration suite: 65 tests passed
- Ruff lint: passed
- Bandit static security scan: passed with no reported findings
- Shell syntax checks: passed
- systemd unit verification: passed
- Dependency consistency with the locked runtime environment: passed

## New coverage

- Exact client identifier confirms one active Plex account.
- Missing identifiers do not establish identity.
- Duplicate identifiers remain unknown.
- Non-Plex activity is not annotated.
- Active and recent public connection collections receive profiles.
- Collector snapshots include confirmed profile data.
- Dashboard contains confirmed and unconfirmed identity treatments.
- Existing offscreen map route and remote traffic reconciliation tests remain passing.

## Remaining live acceptance

The package still requires installation on the development VPS followed by authenticated browser validation and a real remote Plex stream correlation check before merge and production deployment.
