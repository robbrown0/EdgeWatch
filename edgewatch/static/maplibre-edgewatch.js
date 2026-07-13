"use strict";

(function attachEdgeWatchMapLibre(global) {
  const SOURCE_IDS = {
    routes: "edgewatch-routes",
    accuracy: "edgewatch-accuracy",
    peers: "edgewatch-peers",
    origin: "edgewatch-origin",
  };

  const EMPTY_COLLECTION = {
    type: "FeatureCollection",
    features: [],
  };

  let map = null;
  let protocol = null;
  let statusPromise = null;
  let initPromise = null;
  let loaded = false;
  let failed = false;
  let active = false;
  let lastSignature = "";
  let lastRouteSignature = "";
  let routeUpdatePending = false;
  let currentPeers = new Map();
  let currentOrigin = null;
  let currentCallbacks = {};
  let resizeObserver = null;
  let lastError = "";

  // EdgeWatch MapLibre Safari activation fix

  function element(id) {
    return document.getElementById(id);
  }

  function finiteNumber(value, fallback = 0) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
  }

  function validCoordinate(longitude, latitude) {
    const lon = Number(longitude);
    const lat = Number(latitude);
    return (
      Number.isFinite(lon) &&
      Number.isFinite(lat) &&
      lon >= -180 &&
      lon <= 180 &&
      lat >= -85.051129 &&
      lat <= 85.051129
    );
  }

  function librariesAvailable() {
    return Boolean(
      global.maplibregl &&
      global.pmtiles &&
      global.basemaps &&
      typeof global.maplibregl.Map === "function" &&
      typeof global.pmtiles.Protocol === "function" &&
      typeof global.basemaps.layers === "function" &&
      typeof global.basemaps.namedFlavor === "function"
    );
  }

  async function readStatus() {
    if (!statusPromise) {
      statusPromise = fetch("/api/v1/map/status", {
        cache: "no-store",
        credentials: "same-origin",
      })
        .then((response) => {
          if (!response.ok) {
            throw new Error(`Map status ${response.status}`);
          }
          return response.json();
        })
        .catch((error) => ({
          ready: false,
          error: String(error?.message || error),
        }));
    }

    return statusPromise;
  }

  function absoluteUrl(path) {
    const origin =
      global.location?.origin &&
      global.location.origin !== "null"
        ? global.location.origin
        : document.baseURI;

    return new URL(path, origin).href;
  }

  // EdgeWatch literal glyph-template URL
  function absoluteTemplateUrl(path) {
    /*
     * new URL() percent-encodes braces.  Replace the
     * MapLibre template tokens temporarily, build the
     * absolute URL, then restore the literal tokens.
     */
    const fontstackToken =
      "__EDGEWATCH_FONTSTACK__";

    const rangeToken =
      "__EDGEWATCH_RANGE__";

    return absoluteUrl(
      path
        .replace(
          "{fontstack}",
          fontstackToken
        )
        .replace(
          "{range}",
          rangeToken
        )
    )
      .replace(
        fontstackToken,
        "{fontstack}"
      )
      .replace(
        rangeToken,
        "{range}"
      );
  }

  function directionColorExpression() {
    return [
      "match",
      ["get", "direction"],
      "inbound", "#38bdf8",
      "outbound", "#818cf8",
      "mixed", "#fbbf24",
      "#94a3b8",
    ];
  }

  function categoryColorExpression() {
    return [
      "match",
      ["get", "category"],
      "streaming", "#22c55e",
      "admin", "#38bdf8",
      "service", "#a78bfa",
      "known", "#f59e0b",
      "review", "#fb7185",
      directionColorExpression(),
    ];
  }

  function opacityExpression(activeOpacity, recentOpacity) {
    return [
      "case",
      ["==", ["get", "active"], true],
      activeOpacity,
      recentOpacity,
    ];
  }

  function booleanProperty(value, fallback = false) {
    if (value === undefined || value === null) return fallback;
    if (typeof value === "string") {
      return !["", "0", "false", "no", "off"].includes(
        value.trim().toLowerCase()
      );
    }
    return Boolean(value);
  }

  function clusterDirection(properties = {}) {
    const counts = {
      inbound: Math.max(0, finiteNumber(properties.inboundCount, 0)),
      outbound: Math.max(0, finiteNumber(properties.outboundCount, 0)),
      mixed: Math.max(0, finiteNumber(properties.mixedCount, 0)),
    };

    const singleDirections = ["inbound", "outbound"].filter(
      (direction) => counts[direction] > 0
    );

    if (counts.mixed > 0 || singleDirections.length !== 1) {
      return "mixed";
    }

    return singleDirections[0];
  }

  function visibleRouteFeatures(origin, renderedFeatures) {
    if (
      !origin ||
      !validCoordinate(origin.longitude, origin.latitude) ||
      !Array.isArray(renderedFeatures)
    ) {
      return [];
    }

    const originCoordinates = [
      finiteNumber(origin.longitude),
      finiteNumber(origin.latitude),
    ];
    const seen = new Set();
    const routes = [];

    for (const feature of renderedFeatures) {
      const coordinates = feature?.geometry?.coordinates;
      if (
        feature?.geometry?.type !== "Point" ||
        !Array.isArray(coordinates) ||
        !validCoordinate(coordinates[0], coordinates[1])
      ) {
        continue;
      }

      const properties = feature.properties || {};
      const clustered =
        properties.point_count !== undefined ||
        booleanProperty(properties.cluster, false);
      const clusterId = properties.cluster_id;
      const ip = String(properties.ip || "");
      const key = clustered
        ? `cluster:${clusterId ?? coordinates.join(",")}`
        : `peer:${ip || feature.id || coordinates.join(",")}`;

      if (seen.has(key)) continue;
      seen.add(key);

      const direction = clustered
        ? clusterDirection(properties)
        : String(properties.direction || "outbound");
      const connections = clustered
        ? Math.max(
            1,
            finiteNumber(
              properties.connectionsTotal,
              properties.point_count
            )
          )
        : Math.max(1, finiteNumber(properties.connections, 1));
      const active = clustered
        ? finiteNumber(properties.activeCount, 0) > 0
        : booleanProperty(properties.active, true);

      routes.push({
        type: "Feature",
        properties: {
          ip: clustered ? key : ip,
          direction,
          active,
          connections,
          clustered,
          pointCount: clustered
            ? Math.max(1, finiteNumber(properties.point_count, 1))
            : 1,
        },
        geometry: {
          type: "LineString",
          coordinates: [
            originCoordinates,
            [finiteNumber(coordinates[0]), finiteNumber(coordinates[1])],
          ],
        },
      });
    }

    return routes;
  }

  function routeInputFeatures(renderedFeatures, allPeerFeatures, bounds) {
    const routeInputs = Array.isArray(renderedFeatures)
      ? [...renderedFeatures]
      : [];

    if (
      !Array.isArray(allPeerFeatures) ||
      !bounds ||
      typeof bounds.contains !== "function"
    ) {
      return routeInputs;
    }

    for (const feature of allPeerFeatures) {
      const coordinates = feature?.geometry?.coordinates;

      if (
        feature?.geometry?.type !== "Point" ||
        !Array.isArray(coordinates) ||
        !validCoordinate(coordinates[0], coordinates[1])
      ) {
        continue;
      }

      if (!bounds.contains(coordinates)) {
        routeInputs.push(feature);
      }
    }

    return routeInputs;
  }

  function routeSignature(features) {
    const rows = features.map((feature) => {
      const properties = feature.properties || {};
      const endpoint = feature.geometry?.coordinates?.[1] || [];
      return [
        String(properties.ip || ""),
        endpoint[0] ?? null,
        endpoint[1] ?? null,
        String(properties.direction || ""),
        finiteNumber(properties.connections, 0),
        properties.active === true,
      ];
    });

    rows.sort((left, right) =>
      JSON.stringify(left).localeCompare(JSON.stringify(right))
    );
    return JSON.stringify(rows);
  }

  function createStyle(archiveUrl) {
    const sourceUrl = `pmtiles://${absoluteUrl(archiveUrl)}`;
    const baseLayers = global.basemaps.layers(
      "protomaps",
      global.basemaps.namedFlavor("dark"),
      { lang: "en" }
    );

    return {
      version: 8,
      glyphs: absoluteTemplateUrl(
        "/static/maps/fonts/{fontstack}/{range}.pbf"
      ),
      sprite: absoluteUrl(
        "/static/maps/sprites/v4/dark"
      ),
      sources: {
        protomaps: {
          type: "vector",
          url: sourceUrl,
          attribution:
            '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> · Protomaps',
        },
        [SOURCE_IDS.routes]: {
          type: "geojson",
          data: EMPTY_COLLECTION,
        },
        [SOURCE_IDS.accuracy]: {
          type: "geojson",
          data: EMPTY_COLLECTION,
        },
        [SOURCE_IDS.peers]: {
          type: "geojson",
          data: EMPTY_COLLECTION,
          cluster: true,
          clusterRadius: 44,
          clusterMaxZoom: 13,
          clusterProperties: {
            connectionsTotal: ["+", ["get", "connections"]],
            activeCount: [
              "+",
              ["case", ["==", ["get", "active"], true], 1, 0],
            ],
            inboundCount: [
              "+",
              ["case", ["==", ["get", "direction"], "inbound"], 1, 0],
            ],
            outboundCount: [
              "+",
              ["case", ["==", ["get", "direction"], "outbound"], 1, 0],
            ],
            mixedCount: [
              "+",
              ["case", ["==", ["get", "direction"], "mixed"], 1, 0],
            ],
          },
        },
        [SOURCE_IDS.origin]: {
          type: "geojson",
          data: EMPTY_COLLECTION,
        },
      },
      layers: [
        ...baseLayers,
        {
          id: "edgewatch-accuracy-fill",
          type: "fill",
          source: SOURCE_IDS.accuracy,
          paint: {
            "fill-color": directionColorExpression(),
            "fill-opacity": opacityExpression(0.07, 0.035),
          },
        },
        {
          id: "edgewatch-accuracy-line",
          type: "line",
          source: SOURCE_IDS.accuracy,
          paint: {
            "line-color": directionColorExpression(),
            "line-width": 1,
            "line-opacity": opacityExpression(0.32, 0.16),
            "line-dasharray": [3, 3],
          },
        },
        {
          id: "edgewatch-routes-line",
          type: "line",
          source: SOURCE_IDS.routes,
          layout: {
            "line-cap": "round",
            "line-join": "round",
          },
          paint: {
            "line-color": directionColorExpression(),
            "line-width": [
              "interpolate",
              ["linear"],
              ["get", "connections"],
              1, 1.5,
              5, 2.8,
              20, 4.5,
            ],
            "line-opacity": opacityExpression(0.68, 0.22),
            "line-dasharray": [3, 3],
          },
        },
        {
          id: "edgewatch-clusters",
          type: "circle",
          source: SOURCE_IDS.peers,
          filter: ["has", "point_count"],
          paint: {
            "circle-color": [
              "step",
              ["get", "point_count"],
              "#38bdf8",
              4, "#818cf8",
              8, "#a78bfa",
            ],
            "circle-radius": [
              "step",
              ["get", "point_count"],
              18,
              4, 22,
              8, 27,
            ],
            "circle-stroke-color": "rgba(255,255,255,0.9)",
            "circle-stroke-width": 2,
            "circle-opacity": 0.92,
          },
        },
        {
          id: "edgewatch-cluster-count",
          type: "symbol",
          source: SOURCE_IDS.peers,
          filter: ["has", "point_count"],
          layout: {
            "text-field": ["get", "point_count_abbreviated"],
            "text-font": ["Noto Sans Medium"],
            "text-size": 12,
          },
          paint: {
            "text-color": "#f8fafc",
          },
        },
        {
          id: "edgewatch-peer-points",
          type: "circle",
          source: SOURCE_IDS.peers,
          filter: ["!", ["has", "point_count"]],
          paint: {
            "circle-color": directionColorExpression(),
            "circle-radius": [
              "interpolate",
              ["linear"],
              ["get", "connections"],
              1, 7,
              5, 10,
              20, 14,
            ],
            "circle-opacity": opacityExpression(0.96, 0.46),
            "circle-stroke-color": "rgba(255,255,255,0.94)",
            "circle-stroke-width": 1.7,
          },
        },
        {
          id: "edgewatch-peer-labels",
          type: "symbol",
          source: SOURCE_IDS.peers,
          filter: [
            "all",
            ["!", ["has", "point_count"]],
            ["==", ["get", "showLabel"], true],
          ],
          layout: {
            "text-field": ["get", "displayName"],
            "text-font": ["Noto Sans Medium"],
            "text-size": 12,
            "text-offset": [0, 1.4],
            "text-anchor": "top",
            "text-allow-overlap": false,
            "text-optional": true,
            "symbol-sort-key": ["get", "labelRank"],
          },
          paint: {
            "text-color": "#f1f5f9",
            "text-halo-color": "rgba(3,17,29,0.95)",
            "text-halo-width": 2,
          },
        },
        {
          id: "edgewatch-origin-ring",
          type: "circle",
          source: SOURCE_IDS.origin,
          paint: {
            "circle-color": "rgba(52,211,153,0.06)",
            "circle-radius": 18,
            "circle-stroke-color": "rgba(52,211,153,0.75)",
            "circle-stroke-width": 2,
          },
        },
        {
          id: "edgewatch-origin-point",
          type: "circle",
          source: SOURCE_IDS.origin,
          paint: {
            "circle-color": "#34d399",
            "circle-radius": 8,
            "circle-stroke-color": "#ecfdf5",
            "circle-stroke-width": 2,
          },
        },
        {
          id: "edgewatch-origin-label",
          type: "symbol",
          source: SOURCE_IDS.origin,
          layout: {
            "text-field": ["get", "displayName"],
            "text-font": ["Noto Sans Medium"],
            "text-size": 12,
            "text-offset": [0, 1.45],
            "text-anchor": "top",
          },
          paint: {
            "text-color": "#a7f3d0",
            "text-halo-color": "rgba(3,17,29,0.96)",
            "text-halo-width": 2,
          },
        },
      ],
    };
  }

  function setInteractiveCursor(layerId) {
    map.on("mouseenter", layerId, () => {
      map.getCanvas().style.cursor = "pointer";
    });
    map.on("mouseleave", layerId, () => {
      map.getCanvas().style.cursor = "";
    });
  }

  async function clusterExpansionZoom(source, clusterId) {
    if (!source || typeof source.getClusterExpansionZoom !== "function") {
      throw new Error("Cluster source is unavailable");
    }

    if (source.getClusterExpansionZoom.length >= 2) {
      return new Promise((resolve, reject) => {
        source.getClusterExpansionZoom(clusterId, (error, zoom) => {
          if (error) reject(error);
          else resolve(zoom);
        });
      });
    }

    return source.getClusterExpansionZoom(clusterId);
  }

  async function clusterLeaves(source, clusterId, limit = 100) {
    if (!source || typeof source.getClusterLeaves !== "function") {
      return [];
    }

    if (source.getClusterLeaves.length >= 4) {
      return new Promise((resolve, reject) => {
        source.getClusterLeaves(
          clusterId,
          limit,
          0,
          (error, leaves) => {
            if (error) reject(error);
            else resolve(leaves || []);
          }
        );
      });
    }

    return source.getClusterLeaves(clusterId, limit, 0);
  }

  async function openClusterDetails(source, clusterId) {
    const leaves = await clusterLeaves(source, clusterId);
    const peers = leaves
      .map((leaf) =>
        currentPeers.get(String(leaf?.properties?.ip || ""))
      )
      .filter(Boolean);

    if (peers.length && typeof currentCallbacks.onCluster === "function") {
      currentCallbacks.onCluster(peers);
      return true;
    }

    return false;
  }

  function bindInteractions() {
    map.on("click", "edgewatch-clusters", async (event) => {
      const feature = event.features?.[0];
      const clusterId = feature?.properties?.cluster_id;
      if (clusterId === undefined) return;

      try {
        const source = map.getSource(SOURCE_IDS.peers);
        const zoom = await clusterExpansionZoom(source, clusterId);
        const maximumZoom = finiteNumber(map.getMaxZoom?.(), 13);
        const currentZoom = finiteNumber(map.getZoom?.(), 0);

        if (zoom > maximumZoom || currentZoom >= maximumZoom - 0.05) {
          const opened = await openClusterDetails(source, clusterId);
          if (opened) return;
        }

        map.easeTo({
          center: feature.geometry.coordinates,
          zoom: Math.min(zoom, maximumZoom),
          duration: 500,
        });
      } catch (error) {
        console.warn("Cluster expansion failed", error);
        try {
          await openClusterDetails(
            map.getSource(SOURCE_IDS.peers),
            clusterId
          );
        } catch (detailError) {
          console.warn("Cluster detail list failed", detailError);
        }
      }
    });

    const openPeer = (event) => {
      const feature = event.features?.[0];
      const ip = String(feature?.properties?.ip || "");
      const peer = currentPeers.get(ip);
      if (peer && typeof currentCallbacks.onPeer === "function") {
        currentCallbacks.onPeer(peer);
      }
    };

    map.on("click", "edgewatch-peer-points", openPeer);
    map.on("click", "edgewatch-peer-labels", openPeer);

    const openOrigin = () => {
      if (
        currentOrigin &&
        typeof currentCallbacks.onOrigin === "function"
      ) {
        currentCallbacks.onOrigin(currentOrigin);
      }
    };

    map.on("click", "edgewatch-origin-point", openOrigin);
    map.on("click", "edgewatch-origin-label", openOrigin);

    for (const layerId of [
      "edgewatch-clusters",
      "edgewatch-cluster-count",
      "edgewatch-peer-points",
      "edgewatch-peer-labels",
      "edgewatch-origin-point",
      "edgewatch-origin-label",
    ]) {
      setInteractiveCursor(layerId);
    }
  }

  function customFitControl() {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "maplibregl-ctrl-icon edgewatch-map-fit";
    button.title = "Fit all mapped clients";
    button.setAttribute("aria-label", "Fit all mapped clients");
    button.textContent = "Fit";

    const container = document.createElement("div");
    container.className = "maplibregl-ctrl maplibregl-ctrl-group";
    container.appendChild(button);

    return {
      onAdd() {
        button.addEventListener("click", () => fit(true));
        return container;
      },
      onRemove() {
        button.remove();
        container.remove();
      },
    };
  }

  async function init() {
    if (initPromise) return initPromise;

    initPromise = (async () => {
      if (failed || !librariesAvailable()) return false;

      const status = await readStatus();
      if (!status.ready) return false;

      const container = element("connectionMapLibre");
      if (!container) return false;

      /*
       * EdgeWatch MapLibre visible-size initialization
       *
       * Safari may fail to initialize WebGL while the
       * map container is display:none.  Give it its real
       * dimensions while keeping it invisible until load.
       */
      container.classList.remove("hidden");
      container.classList.add(
        "maplibre-initializing"
      );

      try {
        const workerUrl =
          "/static/vendor/maplibre-gl-csp-worker.js";

        if (
          typeof global.maplibregl.setWorkerUrl ===
          "function"
        ) {
          global.maplibregl.setWorkerUrl(workerUrl);
        } else {
          global.maplibregl.workerUrl = workerUrl;
        }

        protocol = new global.pmtiles.Protocol();
        global.maplibregl.addProtocol("pmtiles", protocol.tile);

        map = new global.maplibregl.Map({
          container,
          style: createStyle(status.archive_url),
          center: [-98.5, 38.5],
          zoom: 2.8,
          minZoom: 1.2,
          maxZoom: 13,
          attributionControl: false,
          dragRotate: false,
          pitchWithRotate: false,
          touchPitch: false,
          cooperativeGestures: false,
          fadeDuration: 120,
          preserveDrawingBuffer: false,
        });

        map.addControl(
          new global.maplibregl.NavigationControl({
            showCompass: false,
            visualizePitch: false,
          }),
          "top-left"
        );
        map.addControl(customFitControl(), "top-left");
        map.addControl(
          new global.maplibregl.AttributionControl({
            compact: true,
          }),
          "bottom-right"
        );

        if (typeof global.ResizeObserver === "function") {
          resizeObserver = new global.ResizeObserver(() => {
            map?.resize();
          });
          resizeObserver.observe(container);
        }

        await new Promise((resolve, reject) => {
          let settled = false;

          const timeout = global.setTimeout(() => {
            if (settled) return;
            settled = true;

            const suffix = lastError
              ? `  Last map error: ${lastError}`
              : "";

            reject(
              new Error(
                `Local basemap did not load within 30 seconds.${suffix}`
              )
            );
          }, 30000);

          /*
           * An early error may be a recoverable tile,
           * sprite or font warning.  Record it without
           * abandoning the map before the load event.
           */
          map.once("error", (event) => {
            lastError = String(
              event?.error?.message ||
              event?.error ||
              "Unknown map error"
            );

            console.warn(
              "MapLibre initialization warning",
              lastError
            );
          });

          map.once("load", () => {
            if (settled) return;

            settled = true;
            global.clearTimeout(timeout);
            lastError = "";
            resolve();
          });
        });

        container.classList.remove(
          "maplibre-initializing"
        );

        loaded = true;
        bindInteractions();
        map.on("moveend", scheduleVisibleRoutes);

        map.on("error", (event) => {
          const message = String(
            event?.error?.message ||
            event?.error ||
            "Map error"
          );

          lastError = message;

          console.error(
            "EdgeWatch map error",
            message
          );
        });

        if (currentOrigin || currentPeers.size) {
          updateSources();
          fit(false);
        }

        return true;
      } catch (error) {
        lastError = String(
          error?.message ||
          error ||
          "Unknown MapLibre initialization error"
        );

        console.error(
          "MapLibre initialization failed",
          lastError
        );

        failed = true;
        active = false;
        loaded = false;
        resizeObserver?.disconnect();
        resizeObserver = null;
        try {
          map?.remove();
        } catch (_removeError) {
          // The legacy SVG remains available as the safe fallback.
        }
        map = null;

        container.classList.remove(
          "maplibre-initializing"
        );

        container.classList.add("hidden");
        return false;
      }
    })();

    return initPromise;
  }

  function destinationPoint(longitude, latitude, bearingDegrees, distanceKm) {
    const earthRadiusKm = 6371.0088;
    const angularDistance = distanceKm / earthRadiusKm;
    const bearing = (bearingDegrees * Math.PI) / 180;
    const lat1 = (latitude * Math.PI) / 180;
    const lon1 = (longitude * Math.PI) / 180;

    const lat2 = Math.asin(
      Math.sin(lat1) * Math.cos(angularDistance) +
      Math.cos(lat1) * Math.sin(angularDistance) * Math.cos(bearing)
    );

    const lon2 = lon1 + Math.atan2(
      Math.sin(bearing) * Math.sin(angularDistance) * Math.cos(lat1),
      Math.cos(angularDistance) - Math.sin(lat1) * Math.sin(lat2)
    );

    return [
      ((((lon2 * 180) / Math.PI) + 540) % 360) - 180,
      (lat2 * 180) / Math.PI,
    ];
  }

  function accuracyPolygon(peer) {
    const longitude = finiteNumber(peer.longitude, NaN);
    const latitude = finiteNumber(peer.latitude, NaN);
    const radiusKm = Math.min(
      1000,
      Math.max(0, finiteNumber(peer.accuracyRadiusKm, 0))
    );

    if (!validCoordinate(longitude, latitude) || radiusKm <= 0) {
      return null;
    }

    const ring = [];
    for (let index = 0; index <= 48; index += 1) {
      ring.push(destinationPoint(
        longitude,
        latitude,
        (index / 48) * 360,
        radiusKm
      ));
    }

    return {
      type: "Feature",
      properties: {
        ip: peer.ip,
        category: peer.category,
        direction: peer.direction,
        active: peer.active !== false,
        radiusKm,
      },
      geometry: {
        type: "Polygon",
        coordinates: [ring],
      },
    };
  }

  function featureCollections(payload) {
    const peers = Array.isArray(payload.peers)
      ? payload.peers.filter((peer) =>
          validCoordinate(peer.longitude, peer.latitude)
        )
      : [];

    const origin = payload.origin &&
      validCoordinate(payload.origin.longitude, payload.origin.latitude)
      ? payload.origin
      : null;

    const labeled = new Set(
      [...peers]
        .sort((a, b) =>
          finiteNumber(b.connections) - finiteNumber(a.connections)
        )
        .slice(0, 12)
        .map((peer) => String(peer.ip))
    );

    const peerFeatures = peers.map((peer, index) => ({
      type: "Feature",
      id: index + 1,
      properties: {
        ip: String(peer.ip || ""),
        displayName: String(peer.displayName || peer.ip || "Connection"),
        detail: String(peer.detail || ""),
        direction: String(peer.direction || "outbound"),
        category: String(peer.category || "review"),
        active: peer.active !== false,
        connections: Math.max(1, finiteNumber(peer.connections, 1)),
        showLabel: labeled.has(String(peer.ip)),
        labelRank: index,
        accuracyRadiusKm: finiteNumber(peer.accuracyRadiusKm, 0),
      },
      geometry: {
        type: "Point",
        coordinates: [
          finiteNumber(peer.longitude),
          finiteNumber(peer.latitude),
        ],
      },
    }));

    const routeFeatures = origin
      ? peers.map((peer, index) => ({
          type: "Feature",
          id: index + 1,
          properties: {
            ip: String(peer.ip || ""),
            direction: String(peer.direction || "outbound"),
            active: peer.active !== false,
            connections: Math.max(1, finiteNumber(peer.connections, 1)),
          },
          geometry: {
            type: "LineString",
            coordinates: [
              [
                finiteNumber(origin.longitude),
                finiteNumber(origin.latitude),
              ],
              [
                finiteNumber(peer.longitude),
                finiteNumber(peer.latitude),
              ],
            ],
          },
        }))
      : [];

    const accuracyFeatures = peers
      .map(accuracyPolygon)
      .filter(Boolean);

    const originFeatures = origin
      ? [{
          type: "Feature",
          properties: {
            displayName: String(origin.displayName || "EdgeWatch VPS"),
            ip: String(origin.ip || ""),
          },
          geometry: {
            type: "Point",
            coordinates: [
              finiteNumber(origin.longitude),
              finiteNumber(origin.latitude),
            ],
          },
        }]
      : [];

    return {
      peers: { type: "FeatureCollection", features: peerFeatures },
      routes: { type: "FeatureCollection", features: routeFeatures },
      accuracy: { type: "FeatureCollection", features: accuracyFeatures },
      origin: { type: "FeatureCollection", features: originFeatures },
      coordinates: [
        ...originFeatures.map((feature) => feature.geometry.coordinates),
        ...peerFeatures.map((feature) => feature.geometry.coordinates),
      ],
    };
  }

  function setRouteFeatures(features) {
    const source = map?.getSource(SOURCE_IDS.routes);
    if (!source || typeof source.setData !== "function") return;

    const nextSignature = routeSignature(features);
    if (nextSignature === lastRouteSignature) return;

    lastRouteSignature = nextSignature;
    source.setData({
      type: "FeatureCollection",
      features,
    });
  }

  function updateVisibleRoutes() {
    routeUpdatePending = false;
    if (!map || !loaded || !currentOrigin) {
      setRouteFeatures([]);
      return;
    }

    let renderedFeatures = [];
    try {
      renderedFeatures = map.queryRenderedFeatures({
        layers: ["edgewatch-clusters", "edgewatch-peer-points"],
      });
    } catch (error) {
      console.warn("Visible map route query failed", error);
      return;
    }

    let routeInputs = [...renderedFeatures];

    try {
      const bounds =
        typeof map.getBounds === "function" ? map.getBounds() : null;

      const allPeerFeatures = featureCollections({
        origin: currentOrigin,
        peers: [...currentPeers.values()],
      }).peers.features;

      routeInputs = routeInputFeatures(
        renderedFeatures,
        allPeerFeatures,
        bounds
      );
    } catch (error) {
      console.warn("Off-screen map route calculation failed", error);
    }

    setRouteFeatures(
      visibleRouteFeatures(currentOrigin, routeInputs)
    );
  }

  function scheduleVisibleRoutes() {
    if (!map || !loaded || routeUpdatePending) return;
    routeUpdatePending = true;

    const nextFrame =
      typeof global.requestAnimationFrame === "function"
        ? global.requestAnimationFrame.bind(global)
        : (callback) => global.setTimeout(callback, 0);

    nextFrame(() => nextFrame(updateVisibleRoutes));
  }

  function updateSources() {
    if (!map || !loaded) return;

    const payload = {
      origin: currentOrigin,
      peers: [...currentPeers.values()],
    };
    const collections = featureCollections(payload);

    map.getSource(SOURCE_IDS.accuracy)?.setData(collections.accuracy);
    const peerUpdate = map
      .getSource(SOURCE_IDS.peers)
      ?.setData(collections.peers, true);
    map.getSource(SOURCE_IDS.origin)?.setData(collections.origin);

    if (!currentOrigin || currentPeers.size === 0) {
      setRouteFeatures([]);
      return;
    }

    if (peerUpdate && typeof peerUpdate.then === "function") {
      peerUpdate
        .then(scheduleVisibleRoutes)
        .catch((error) => {
          routeUpdatePending = false;
          console.warn("Peer clustering update failed", error);
        });
    } else {
      scheduleVisibleRoutes();
    }
  }

  function signature(payload) {
    const origin = payload.origin;
    const peers = Array.isArray(payload.peers) ? payload.peers : [];
    return [
      origin
        ? `${origin.ip || "origin"}:${origin.longitude}:${origin.latitude}`
        : "",
      ...peers
        .map((peer) =>
          `${peer.ip}:${peer.longitude}:${peer.latitude}:${peer.active !== false}`
        )
        .sort(),
    ].join("|");
  }

  function fit(force = false) {
    if (!map || !loaded) return;

    const collections = featureCollections({
      origin: currentOrigin,
      peers: [...currentPeers.values()],
    });

    if (!collections.coordinates.length) return;

    if (collections.coordinates.length === 1) {
      map.easeTo({
        center: collections.coordinates[0],
        zoom: 7,
        duration: force ? 400 : 0,
      });
      return;
    }

    const bounds = new global.maplibregl.LngLatBounds();
    for (const coordinate of collections.coordinates) {
      bounds.extend(coordinate);
    }

    map.fitBounds(bounds, {
      padding: { top: 78, right: 72, bottom: 78, left: 72 },
      maxZoom: 8.5,
      duration: force ? 450 : 0,
      linear: true,
    });
  }

  async function render(payload, callbacks = {}) {
    if (failed) return false;

    const initialized = await init();
    if (!initialized || failed || !map) return false;

    currentOrigin = payload.origin || null;
    currentPeers = new Map(
      (Array.isArray(payload.peers) ? payload.peers : [])
        .map((peer) => [String(peer.ip || ""), peer])
    );
    currentCallbacks = callbacks;

    const nextSignature = signature(payload);
    const changed = nextSignature !== lastSignature;
    lastSignature = nextSignature;

    updateSources();

    const container = element("connectionMapLibre");
    container?.classList.remove("hidden");
    active = true;
    map.resize();

    if (loaded && changed) fit(false);
    return true;
  }

  function show() {
    if (!map || failed) return false;
    element("connectionMapLibre")?.classList.remove("hidden");
    active = true;
    map.resize();
    scheduleVisibleRoutes();
    return true;
  }

  function hide() {
    element("connectionMapLibre")?.classList.add("hidden");
    active = false;
  }

  function destroy() {
    resizeObserver?.disconnect();
    resizeObserver = null;
    map?.remove();
    map = null;
    loaded = false;
    active = false;
    routeUpdatePending = false;
    lastRouteSignature = "";
    if (protocol) {
      try {
        global.maplibregl?.removeProtocol("pmtiles");
      } catch (_error) {
        // Nothing else to clean up.
      }
    }
    protocol = null;
    initPromise = null;
  }

  global.EdgeWatchMapLibre = {
    canAttempt: () => !failed && librariesAvailable(),
    isActive: () => active,
    isReady: () => loaded && !failed,
    render,
    show,
    hide,
    fit,
    destroy,
    resetStatus: () => {
      statusPromise = null;
      initPromise = null;
      failed = false;
      lastError = "";
    },

    diagnostics: () => ({
      failed,
      loaded,
      active,
      lastError,

      libraries: {
        maplibre: Boolean(
          global.maplibregl
        ),

        setWorkerUrl: Boolean(
          global.maplibregl &&
          typeof global.maplibregl.setWorkerUrl ===
            "function"
        ),

        pmtiles: Boolean(
          global.pmtiles
        ),

        basemaps: Boolean(
          global.basemaps
        ),
      },
    }),

    __test: {
      validCoordinate,
      destinationPoint,
      accuracyPolygon,
      featureCollections,
      signature,
      booleanProperty,
      clusterDirection,
      visibleRouteFeatures,
      routeInputFeatures,
      routeSignature,
      clusterExpansionZoom,
      clusterLeaves,
    },
  };
})(window);
