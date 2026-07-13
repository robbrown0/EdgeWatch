from __future__ import annotations

import json
import subprocess
import unittest
from pathlib import Path


class FrontendLogicTests(unittest.TestCase):
    def test_remote_plex_estimates_exclude_local_sessions(self) -> None:
        app_path = Path(__file__).resolve().parents[1] / "edgewatch" / "static" / "app.js"
        source = app_path.read_text()
        start = source.index("function isPrivatePlexAddress")
        end = source.index("function streamClientDisplayName")
        functions = source[start:end]

        script = f"""
const state = {{ liveTrafficSamples: [] }};
function number(value, fallback = 0) {{
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}}
function ewNormalizeAddress(value) {{
  const address = String(value || '').replace(/^\\[|\\]$/g, '').split('%', 1)[0];
  return address.toLowerCase().startsWith('::ffff:') ? address.slice(7) : address;
}}
{functions}
const snapshot = {{
  generated_at: '2026-07-12T23:26:00Z',
  network: {{ rx_rate_bps: 100000, tx_rate_bps: 0, connections: {{ public_peers: [{{ip:'198.51.100.10'}}, {{ip:'203.0.113.20'}}] }} }},
  plex: {{ sessions: [
    {{location:'lan', address:'10.200.1.18', state:'playing', bandwidth_kbps:20600}},
    {{location:'lan', address:'10.200.1.17', state:'playing', bandwidth_kbps:10500}},
    {{location:'wan', address:'203.0.113.20', state:'paused', bandwidth_kbps:9100}},
    {{location:'wan', address:'198.51.100.10', state:'playing', bandwidth_kbps:2100}}
  ] }}
}};
const estimates = plexTrafficEstimates(snapshot);
const firstAverage = rollingTrafficAverage(snapshot, 30);
snapshot.generated_at = '2026-07-12T23:26:05Z';
snapshot.network.tx_rate_bps = 500000;
const secondAverage = rollingTrafficAverage(snapshot, 30);
console.log(JSON.stringify({{estimates, firstAverage, secondAverage}}));
"""
        completed = subprocess.run(
            ["node", "-e", script],
            check=True,
            capture_output=True,
            text=True,
        )
        payload = json.loads(completed.stdout)
        estimates = payload["estimates"]
        self.assertEqual(estimates["activeMbps"], 2.1)
        self.assertEqual(estimates["pausedMbps"], 9.1)
        self.assertEqual(estimates["activeRemoteCount"], 1)
        self.assertEqual(estimates["pausedRemoteCount"], 1)
        self.assertEqual(estimates["localCount"], 2)
        self.assertEqual(payload["firstAverage"]["tx"], 0)
        self.assertEqual(payload["secondAverage"]["tx"], 250000)
        self.assertEqual(payload["secondAverage"]["samples"], 2)


if __name__ == "__main__":
    unittest.main()
