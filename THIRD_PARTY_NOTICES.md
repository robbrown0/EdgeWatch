# Third-party notices

EdgeWatch application code is governed by the project LICENSE file. Third-party software, fonts, and data remain governed by their own licenses.

## Bundled browser libraries

| Component | Bundled version | License | Files |
| --- | ---: | --- | --- |
| MapLibre GL JS | 5.24.0 | BSD 3-Clause and included component notices | `edgewatch/static/vendor/maplibre-gl-*` |
| PMTiles JavaScript | 4.4.1 | BSD 3-Clause | `edgewatch/static/vendor/pmtiles.js` |
| Protomaps basemap styles | 5.7.2 | BSD 3-Clause, with included CC0 and MIT notices | `edgewatch/static/vendor/basemaps.js` |

Full notices are retained in:

```text
licenses/MAPLIBRE-LICENSE.txt
licenses/PMTILES-LICENSE.txt
licenses/PROTOMAPS-BASEMAPS-LICENSE.md
```

## Fonts

The local Noto Sans map font files are licensed under the SIL Open Font License 1.1.

The full license is retained at:

```text
edgewatch/static/maps/fonts/OFL.txt
```

## Natural Earth

`edgewatch/static/world-map.svg` is derived from Natural Earth country geometry. Natural Earth vector and raster map data is public domain.

Project and terms:

- https://www.naturalearthdata.com/
- https://www.naturalearthdata.com/about/terms-of-use/

## Optional PMTiles basemap archive

The large `edgewatch.pmtiles` archive is intentionally excluded from the source and release archives. When installed from Protomaps builds, it is a produced work derived primarily from OpenStreetMap data and requires OpenStreetMap attribution under the Open Database License.

The EdgeWatch map displays:

```text
OpenStreetMap · Protomaps
```

Relevant terms:

- https://www.openstreetmap.org/copyright
- https://docs.protomaps.com/basemaps/downloads

## Python runtime dependencies

Runtime dependencies are downloaded during installation from the exact versions in `requirements.lock`. They are not copied into the GitHub source archive or application release archive.

| Package | Version | License |
| --- | ---: | --- |
| annotated-doc | 0.0.4 | MIT |
| annotated-types | 0.7.0 | MIT |
| anyio | 4.14.1 | MIT |
| click | 8.4.2 | BSD 3-Clause |
| fastapi | 0.139.0 | MIT |
| h11 | 0.16.0 | MIT |
| idna | 3.18 | BSD 3-Clause |
| maxminddb | 3.1.1 | Apache License 2.0 |
| pydantic | 2.13.4 | MIT |
| pydantic-core | 2.46.4 | MIT |
| starlette | 1.3.1 | BSD 3-Clause |
| tomli | 2.4.1 | MIT |
| typing-inspection | 0.4.2 | MIT |
| typing-extensions | 4.16.0 | Python Software Foundation License |
| uvicorn | 0.51.0 | BSD 3-Clause |

Each installed Python distribution includes its license metadata in the virtual environment created on the target host.

## External services and trademarks

Microsoft Entra, Linode, Plex, WireGuard, Caddy, oauth2-proxy, MaxMind, ntfy, OpenStreetMap, Natural Earth, MapLibre, and Protomaps are names or marks of their respective owners. Their mention describes interoperability and does not imply endorsement.
