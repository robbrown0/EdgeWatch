from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


class FrontendTests(unittest.TestCase):
    def test_frontend_is_self_contained_and_safe(self) -> None:
        root = Path(__file__).resolve().parents[1] / "edgewatch" / "static"
        html = (root / "index.html").read_text()
        js = (root / "app.js").read_text()
        self.assertNotIn("https://", html)
        self.assertIn('/static/app.css', html)
        self.assertIn('/static/app.js', html)
        self.assertNotIn("innerHTML", js)
        self.assertIn("EventSource", js)
        self.assertIn("connectionMap", html)
        self.assertIn("streamGrid", html)
        self.assertTrue((root / "favicon.svg").exists())
        self.assertTrue((root / "world-map.svg").exists())
        self.assertGreater((root / "world-map.svg").stat().st_size, 50_000)
        self.assertIn("Edge topology", html)
        self.assertIn("flowScopeControl", html)
        self.assertIn("internal_peers", js)
        self.assertNotIn("item.certificate.days_remaining", js)
        self.assertIn("acknowledgedPanel", html)
        self.assertIn("finding-acknowledgements", js)
        self.assertIn('role", "switch"', js)
        self.assertNotIn("monitor.example.com/signed-out", js)
        self.assertNotIn("tenantid=", js.lower())
        self.assertIn('fetch(\n        "/api/v1/identity"', js)
        self.assertIn('"Application (client) ID"', js)
        self.assertIn('"Tenant ID"', js)
        self.assertIn("edgewatchIdentity.directoryName", js)
        self.assertNotIn("Configured Microsoft Entra tenant", js)
        self.assertIn("snapshot.topology", js)
        self.assertIn("serviceDefinitions", js)

    def test_offscreen_peer_route_remains_after_zoom(self) -> None:
        project_root = Path(__file__).resolve().parents[1]

        script = r"""
global.window = global;
require("./edgewatch/static/maplibre-edgewatch.js");

const {
  routeInputFeatures,
  visibleRouteFeatures,
} = global.EdgeWatchMapLibre.__test;

const origin = {
  longitude: -74.0,
  latitude: 40.7,
};

const visiblePeer = {
  type: "Feature",
  properties: {
    ip: "198.51.100.10",
    direction: "outbound",
    connections: 1,
    active: true,
  },
  geometry: {
    type: "Point",
    coordinates: [-74.1, 40.8],
  },
};

const offscreenPeer = {
  type: "Feature",
  properties: {
    ip: "203.0.113.20",
    direction: "outbound",
    connections: 1,
    active: true,
  },
  geometry: {
    type: "Point",
    coordinates: [-84.8, 38.2],
  },
};

const zoomedBounds = {
  contains: ([longitude, latitude]) =>
    longitude > -80 &&
    longitude < -70 &&
    latitude > 35 &&
    latitude < 45,
};

const routeInputs = routeInputFeatures(
  [visiblePeer],
  [visiblePeer, offscreenPeer],
  zoomedBounds
);

const routes = visibleRouteFeatures(origin, routeInputs);

if (routes.length !== 2) {
  throw new Error(
    `Expected 2 routes after zoom, received ${routes.length}`
  );
}

const offscreenRouteExists = routes.some((route) => {
  const endpoint = route.geometry.coordinates[1];

  return endpoint[0] === -84.8 && endpoint[1] === 38.2;
});

if (!offscreenRouteExists) {
  throw new Error(
    "The route to the offscreen peer disappeared after zoom"
  );
}
"""

        result = subprocess.run(
            ["node", "-e", script],
            cwd=project_root,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(
            result.returncode,
            0,
            result.stderr or result.stdout,
        )

    def test_cluster_routes_follow_visible_markers(self) -> None:
        root = Path(__file__).resolve().parents[1] / "edgewatch" / "static"
        map_js = (root / "maplibre-edgewatch.js").read_text()
        html = (root / "index.html").read_text()

        self.assertIn("clusterProperties", map_js)
        self.assertIn("connectionsTotal", map_js)
        self.assertIn("visibleRouteFeatures", map_js)
        self.assertIn("queryRenderedFeatures", map_js)
        self.assertIn('layers: ["edgewatch-clusters", "edgewatch-peer-points"]', map_js)
        self.assertIn('map.on("moveend", scheduleVisibleRoutes)', map_js)
        self.assertNotIn(
            "map.getSource(SOURCE_IDS.routes)?.setData(collections.routes)",
            map_js,
        )
        self.assertIn('/static/maplibre-edgewatch.js?v=0.5.4', html)


    def test_remote_stream_reconciliation_and_client_drilldowns(self) -> None:
        root = Path(__file__).resolve().parents[1] / "edgewatch" / "static"
        html = (root / "index.html").read_text()
        js = (root / "app.js").read_text()
        css = (root / "app.css").read_text()

        self.assertIn("30s average egress", html)
        self.assertIn("Active remote Plex estimate", html)
        self.assertIn('id="remoteClientCard"', html)
        self.assertIn('id="remoteStreamCard"', html)
        self.assertIn('id="flowContext"', html)
        self.assertIn("function plexSessionScope", js)
        self.assertIn("function rollingTrafficAverage", js)
        self.assertIn("function publicPeersWithRemoteSessions", js)
        self.assertIn("function openStreamClientsDrawer", js)
        self.assertIn("function openRemoteClientsDrawer", js)
        self.assertIn("local stream", js)
        self.assertIn("security-finding-evidence .insight-kv", css)
        self.assertIn("client-list-card", css)

    def test_javascript_ids_exist_in_html(self) -> None:
        root = Path(__file__).resolve().parents[1] / "edgewatch" / "static"
        html = (root / "index.html").read_text()
        js = (root / "app.js").read_text()
        html_ids = set(re.findall(r'id="([A-Za-z0-9_-]+)"', html))
        referenced = set(re.findall(r'\$\("([A-Za-z0-9_-]+)"\)', js))
        missing = sorted(referenced - html_ids)
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
