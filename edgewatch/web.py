from __future__ import annotations

import asyncio
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import load_config
from .control import ControlStorage
from .storage import Storage, read_json

PACKAGE_DIR = Path(__file__).resolve().parent
STATIC_DIR = PACKAGE_DIR / "static"


def _security_headers(response: Response) -> None:
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data: blob:; connect-src 'self'; worker-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"


class FindingAcknowledgementChange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fingerprint: str = Field(min_length=1, max_length=200)
    acknowledged: bool


def _allowed_origin_host(hostname: str, allowed_hosts: tuple[str, ...]) -> bool:
    normalized = hostname.lower().rstrip(".")
    for candidate in allowed_hosts:
        allowed = candidate.lower().split(":", 1)[0].rstrip(".")
        if allowed == "*" or normalized == allowed:
            return True
        if allowed.startswith("*.") and normalized.endswith(allowed[1:]):
            return True
    return False


def _validate_mutation_request(request: Request, allowed_hosts: tuple[str, ...]) -> None:
    if request.headers.get("x-edgewatch-action") != "finding-acknowledgement":
        raise HTTPException(status_code=403, detail="Action header is required")

    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(status_code=415, detail="Content-Type must be application/json")

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > 4096:
                raise HTTPException(status_code=413, detail="Request body is too large")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from exc

    origin = request.headers.get("origin", "").strip()
    if not origin:
        raise HTTPException(status_code=403, detail="Origin header is required")

    parsed = urlsplit(origin)
    hostname = parsed.hostname or ""
    if not hostname or not _allowed_origin_host(hostname, allowed_hosts):
        raise HTTPException(status_code=403, detail="Origin is not allowed")

    if parsed.scheme != "https" and hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise HTTPException(status_code=403, detail="HTTPS origin is required")


def _authenticated_actor(request: Request) -> str:
    # These headers are emitted by oauth2-proxy when set_xauthrequest is enabled.
    # Caddy must remove client-supplied copies before forward_auth repopulates them.
    values = [
        request.headers.get("x-auth-request-email"),
        request.headers.get("x-auth-request-preferred-username"),
        request.headers.get("x-auth-request-user"),
    ]
    identity = next((str(value).strip() for value in values if value and str(value).strip()), "")
    if not identity:
        raise HTTPException(status_code=401, detail="Authenticated identity header is missing")
    if len(identity) > 254 or any(ord(character) < 32 for character in identity):
        raise HTTPException(status_code=400, detail="Authenticated identity header is invalid")
    return identity.lower() if "@" in identity else identity


def _identity_metadata(config: object) -> dict[str, object]:
    identity = getattr(config, "identity", None)

    def text(name: str, default: str = "", limit: int = 240) -> str:
        value = str(getattr(identity, name, default) or "").strip()
        return value[:limit]

    payload = {
        "provider": text("provider", "Microsoft Entra ID", 120),
        "directory_name": text("directory_name", limit=200),
        "tenant_id": text("tenant_id", limit=200),
        "application_name": text("application_name", "EdgeWatch", 200),
        "client_id": text("client_id", limit=200),
        "access_label": text(
            "access_label",
            "Assigned enterprise application user",
            240,
        ),
        "session_lifetime": text("session_lifetime", limit=120),
        "session_refresh": text("session_refresh", limit=120),
    }
    payload["configured"] = any(
        payload[key]
        for key in ("directory_name", "tenant_id", "client_id")
    )
    return payload


def _snapshot_insight(snapshot: dict[str, object], fingerprint: str) -> dict[str, object] | None:
    posture = snapshot.get("posture")
    if not isinstance(posture, dict):
        return None
    insights = posture.get("insights")
    if not isinstance(insights, list):
        return None
    for item in insights:
        if isinstance(item, dict) and str(item.get("fingerprint") or "") == fingerprint:
            return item
    return None


def create_app(config_path: str | None = None) -> FastAPI:
    path = config_path or os.environ.get("EDGEWATCH_CONFIG", "/etc/edgewatch/config.toml")
    config = load_config(path)
    storage = Storage(config.database_path)
    control = ControlStorage(config.data_dir / "control" / "edgewatch-control.db")
    control.initialize()
    artwork_dir = config.runtime_dir / "artwork"

    app = FastAPI(
        title="EdgeWatch",
        version="0.5.5",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.config = config
    app.state.storage = storage
    app.state.control = control
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(config.allowed_hosts))
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.middleware("http")
    async def headers_and_request_policy(request: Request, call_next):
        mutation_allowed = (
            request.method == "POST"
            and request.url.path == "/api/v1/finding-acknowledgements"
        )
        if request.method not in {"GET", "HEAD"} and not mutation_allowed:
            response = JSONResponse({"detail": "Method not allowed"}, status_code=405)
        else:
            if mutation_allowed:
                try:
                    _validate_mutation_request(request, tuple(config.allowed_hosts))
                    body = await request.body()
                    if len(body) > 4096:
                        raise HTTPException(status_code=413, detail="Request body is too large")
                except HTTPException as exc:
                    response = JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
                else:
                    response = await call_next(request)
            else:
                response = await call_next(request)
        _security_headers(response)
        if request.url.path == "/api/v1/map/basemap.pmtiles":
            response.headers["Cache-Control"] = "private, max-age=86400"
        elif request.url.path.startswith("/api/") or request.url.path == "/healthz":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", media_type="text/html")

    @app.api_route("/favicon.svg", methods=["GET", "HEAD"], include_in_schema=False)
    async def favicon() -> FileResponse:
        return FileResponse(STATIC_DIR / "favicon.svg", media_type="image/svg+xml")

    @app.api_route(
        "/api/v1/plex/artwork/{key}",
        methods=["GET", "HEAD"],
        include_in_schema=False,
    )
    async def plex_artwork(
        key: str,
    ) -> FileResponse:
        if not re.fullmatch(
            (
                r"[0-9a-f]{64}"
                r"\.(jpg|jpeg|png|webp|gif|avif)"
            ),
            key,
        ):
            raise HTTPException(
                status_code=404,
                detail="Artwork not found",
            )

        artwork_path = artwork_dir / key

        if not artwork_path.is_file():
            raise HTTPException(
                status_code=404,
                detail="Artwork not found",
            )

        media_types = {
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".png": "image/png",
            ".webp": "image/webp",
            ".gif": "image/gif",
            ".avif": "image/avif",
        }

        return FileResponse(
            artwork_path,
            media_type=media_types[
                artwork_path.suffix.lower()
            ],
            headers={
                "Cache-Control": (
                    "private, max-age=86400, immutable"
                ),
            },
        )

    @app.api_route("/api/v1/map/status", methods=["GET", "HEAD"], include_in_schema=False)
    async def map_status() -> JSONResponse:
        vendor_dir = STATIC_DIR / "vendor"
        map_dir = STATIC_DIR / "maps"
        archive = map_dir / "edgewatch.pmtiles"
        required_files = {
            "maplibre": vendor_dir / "maplibre-gl-csp.js",
            "worker": vendor_dir / "maplibre-gl-csp-worker.js",
            "maplibre_css": vendor_dir / "maplibre-gl.css",
            "pmtiles": vendor_dir / "pmtiles.js",
            "basemaps": vendor_dir / "basemaps.js",
            "sprite_json": map_dir / "sprites" / "v4" / "dark.json",
            "sprite_png": map_dir / "sprites" / "v4" / "dark.png",
            "sprite_2x_json": map_dir / "sprites" / "v4" / "dark@2x.json",
            "sprite_2x_png": map_dir / "sprites" / "v4" / "dark@2x.png",
            "font_regular": map_dir / "fonts" / "Noto Sans Regular" / "0-255.pbf",
            "font_medium": map_dir / "fonts" / "Noto Sans Medium" / "0-255.pbf",
            "archive": archive,
        }
        files = {
            name: {
                "available": path.is_file(),
                "size_bytes": path.stat().st_size if path.is_file() else 0,
            }
            for name, path in required_files.items()
        }
        fonts_ready = files["font_regular"]["available"] and files["font_medium"]["available"]
        archive_ready = files["archive"]["available"] and files["archive"]["size_bytes"] >= 127
        ready = (
            all(item["available"] for name, item in files.items() if name != "archive")
            and archive_ready
            and fonts_ready
        )
        return JSONResponse(
            {
                "ready": ready,
                "fonts_available": fonts_ready,
                "files": files,
                "archive_url": "/api/v1/map/basemap.pmtiles",
                "library": "MapLibre GL JS",
                "tile_format": "PMTiles",
            }
        )

    @app.api_route(
        "/api/v1/map/basemap.pmtiles",
        methods=["GET", "HEAD"],
        include_in_schema=False,
    )
    async def map_basemap() -> FileResponse:
        archive = STATIC_DIR / "maps" / "edgewatch.pmtiles"
        if not archive.is_file():
            raise HTTPException(status_code=404, detail="Local basemap is not installed")
        return FileResponse(
            archive,
            media_type="application/vnd.pmtiles",
            headers={
                "Cache-Control": "private, max-age=86400",
                "Accept-Ranges": "bytes",
            },
        )

    @app.api_route("/healthz", methods=["GET", "HEAD"], include_in_schema=False)
    async def healthz() -> JSONResponse:
        snapshot_exists = config.snapshot_path.exists()
        snapshot_age = None
        if snapshot_exists:
            snapshot_age = max(0, int(time.time() - config.snapshot_path.stat().st_mtime))
        healthy = snapshot_exists and snapshot_age is not None and snapshot_age <= config.sample_interval_seconds * 5
        return JSONResponse(
            {
                "status": "ok" if healthy else "degraded",
                "version": "0.5.5",
                "snapshot_exists": snapshot_exists,
                "snapshot_age_seconds": snapshot_age,
            },
            status_code=200 if healthy else 503,
        )

    @app.api_route("/api/v1/identity", methods=["GET", "HEAD"], include_in_schema=False)
    async def identity_metadata(request: Request) -> JSONResponse:
        _authenticated_actor(request)
        return JSONResponse(_identity_metadata(config))

    @app.api_route("/api/v1/snapshot", methods=["GET", "HEAD"], include_in_schema=False)
    async def snapshot() -> JSONResponse:
        try:
            payload = read_json(config.snapshot_path)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=503, detail="Collector snapshot is not ready") from exc
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=503, detail="Collector snapshot is unavailable") from exc
        return JSONResponse(payload)

    @app.get("/api/v1/live", include_in_schema=False)
    async def live(request: Request) -> StreamingResponse:
        async def stream():
            last_mtime = -1.0
            last_keepalive = 0.0
            while True:
                if await request.is_disconnected():
                    break
                try:
                    mtime = config.snapshot_path.stat().st_mtime
                    if mtime != last_mtime:
                        payload = read_json(config.snapshot_path)
                        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
                        yield f"event: snapshot\ndata: {encoded}\n\n"
                        last_mtime = mtime
                        last_keepalive = time.monotonic()
                    elif time.monotonic() - last_keepalive >= 15:
                        yield ": keepalive\n\n"
                        last_keepalive = time.monotonic()
                except FileNotFoundError:
                    if time.monotonic() - last_keepalive >= 5:
                        yield "event: waiting\ndata: {}\n\n"
                        last_keepalive = time.monotonic()
                except (OSError, ValueError):
                    yield "event: degraded\ndata: {}\n\n"
                await asyncio.sleep(1.0)

        return StreamingResponse(
            stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache, no-store",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    @app.post("/api/v1/finding-acknowledgements", include_in_schema=False)
    async def change_finding_acknowledgement(
        change: FindingAcknowledgementChange,
        request: Request,
    ) -> JSONResponse:
        fingerprint = change.fingerprint.strip()
        if (
            not fingerprint
            or any(ord(character) < 32 for character in fingerprint)
            or "/" in fingerprint
            or "\\" in fingerprint
        ):
            raise HTTPException(status_code=400, detail="Finding fingerprint is invalid")

        actor = _authenticated_actor(request)
        now_epoch = int(time.time())

        if change.acknowledged:
            try:
                payload = read_json(config.snapshot_path)
            except (FileNotFoundError, OSError, ValueError) as exc:
                raise HTTPException(
                    status_code=503,
                    detail="Collector snapshot is unavailable",
                ) from exc
            insight = _snapshot_insight(payload, fingerprint)
            if insight is None:
                raise HTTPException(status_code=404, detail="Active finding was not found")

            try:
                acknowledgement, changed = await asyncio.to_thread(
                    control.acknowledge,
                    fingerprint=fingerprint,
                    title=str(insight.get("title") or "Finding"),
                    category=str(insight.get("category") or "General"),
                    severity=str(insight.get("severity") or "info"),
                    actor=actor,
                    now_epoch=now_epoch,
                )
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail="Finding control database is unavailable",
                ) from exc
        else:
            try:
                acknowledgement, changed = await asyncio.to_thread(
                    control.resume,
                    fingerprint=fingerprint,
                    actor=actor,
                    now_epoch=now_epoch,
                )
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail="Finding control database is unavailable",
                ) from exc
            if acknowledgement is None:
                acknowledgement = {
                    "fingerprint": fingerprint,
                    "active": False,
                    "resumed_at": now_epoch,
                    "resumed_by": actor,
                }

        return JSONResponse(
            {
                "changed": changed,
                "acknowledgement": acknowledgement,
            }
        )

    @app.api_route("/api/v1/history", methods=["GET", "HEAD"], include_in_schema=False)
    async def history(
        minutes: int = Query(default=60, ge=5, le=10080),
        points: int = Query(default=1440, ge=60, le=5000),
    ) -> JSONResponse:
        since = int((datetime.now(timezone.utc) - timedelta(minutes=minutes)).timestamp())
        limit = min(points, config.history_points_max)
        try:
            rows = storage.history(since, limit)
        except Exception as exc:
            raise HTTPException(status_code=503, detail="History database is unavailable") from exc
        return JSONResponse({"minutes": minutes, "points": rows})

    return app


def app_factory() -> FastAPI:
    return create_app()
