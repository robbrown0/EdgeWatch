from __future__ import annotations

import hashlib
import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import PlexServer

LOG = logging.getLogger("edgewatch.plex")


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _first_dict(value: Any) -> dict[str, Any]:
    for item in _as_list(value):
        if isinstance(item, dict):
            return item
    return {}


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes"}


def _media_title(item: dict[str, Any]) -> tuple[str, str]:
    media_type = str(item.get("type") or "media")
    title = str(item.get("title") or "Untitled")
    parent = str(item.get("parentTitle") or "")
    grandparent = str(item.get("grandparentTitle") or "")
    year = item.get("year")
    if grandparent:
        primary = grandparent
        secondary = " • ".join(part for part in (parent, title) if part)
    else:
        primary = title
        secondary = str(year) if year else media_type.replace("episode", "TV").title()
    return primary, secondary


def _stream_decision(item: dict[str, Any]) -> tuple[str, str, str]:
    transcode = _as_dict(item.get("TranscodeSession"))
    media = _first_dict(item.get("Media"))
    video_decision = str(transcode.get("videoDecision") or media.get("videoDecision") or "").lower()
    audio_decision = str(transcode.get("audioDecision") or media.get("audioDecision") or "").lower()
    decisions = {video_decision, audio_decision}
    if "transcode" in decisions or transcode:
        mode = "Transcode"
    elif "copy" in decisions:
        mode = "Direct Stream"
    else:
        mode = "Direct Play"
    return mode, video_decision or "unknown", audio_decision or "unknown"


def _source_summary(item: dict[str, Any]) -> str:
    media = _first_dict(item.get("Media"))
    part = _first_dict(media.get("Part"))
    streams = [entry for entry in _as_list(part.get("Stream")) if isinstance(entry, dict)]
    video = next((entry for entry in streams if _int(entry.get("streamType")) == 1), {})
    audio = next((entry for entry in streams if _int(entry.get("streamType")) == 2), {})
    resolution = str(media.get("videoResolution") or video.get("height") or "").upper()
    video_codec = str(media.get("videoCodec") or video.get("codec") or "").upper()
    audio_codec = str(media.get("audioCodec") or audio.get("codec") or "").upper()
    pieces = [part for part in (resolution, video_codec, audio_codec) if part]
    return " • ".join(pieces) or "Source details unavailable"


def _output_summary(item: dict[str, Any]) -> str:
    transcode = _as_dict(item.get("TranscodeSession"))
    if not transcode:
        return "Original stream"
    resolution = str(transcode.get("videoResolution") or "").upper()
    width = _int(transcode.get("width"))
    height = _int(transcode.get("height"))
    if not resolution and width and height:
        resolution = f"{width}×{height}"
    video = str(transcode.get("videoCodec") or "").upper()
    audio = str(transcode.get("audioCodec") or "").upper()
    pieces = [part for part in (resolution, video, audio) if part]
    return " • ".join(pieces) or "Transcoded output"


def parse_sessions(payload: dict[str, Any], server_name: str, now_epoch: int | None = None) -> list[dict[str, object]]:
    container = _as_dict(payload.get("MediaContainer") or payload)
    metadata = [item for item in _as_list(container.get("Metadata")) if isinstance(item, dict)]
    now = now_epoch or int(time.time())
    sessions: list[dict[str, object]] = []

    for item in metadata:
        user = _as_dict(item.get("User"))
        player = _as_dict(item.get("Player"))
        session = _as_dict(item.get("Session"))
        transcode = _as_dict(item.get("TranscodeSession"))
        title, subtitle = _media_title(item)
        mode, video_decision, audio_decision = _stream_decision(item)
        duration = max(0, _int(item.get("duration")))
        offset = max(0, _int(item.get("viewOffset")))
        progress = round(min(100.0, offset * 100 / duration), 1) if duration else 0.0
        bandwidth = max(0, _int(session.get("bandwidth") or transcode.get("bandwidth")))
        location = str(player.get("location") or ("lan" if _bool(player.get("local")) else "wan")).lower()

        sessions.append(
            {
                "server": server_name,
                "session_id": str(session.get("id") or item.get("sessionKey") or item.get("ratingKey") or ""),
                "client_identifier": str(player.get("machineIdentifier") or ""),
                "playback_id": str(player.get("playbackId") or ""),
                "playback_session_id": str(player.get("playbackSessionId") or ""),
                "user": str(user.get("title") or "Unknown user"),
                "user_id": str(user.get("id") or player.get("userID") or ""),
                "title": title,
                "subtitle": subtitle,
                "media_type": str(item.get("type") or "media"),
                "state": str(player.get("state") or "playing").lower(),
                "player": str(player.get("title") or player.get("product") or "Unknown player"),
                "platform": str(player.get("platform") or player.get("product") or ""),
                "address": str(player.get("address") or ""),
                "location": location,
                "secure": _bool(player.get("secure")),
                "relayed": _bool(player.get("relayed")),
                "mode": mode,
                "video_decision": video_decision,
                "audio_decision": audio_decision,
                "source": _source_summary(item),
                "output": _output_summary(item),
                "bandwidth_kbps": bandwidth,
                "progress_percent": progress,
                "view_offset_ms": offset,
                "duration_ms": duration,
                "thumb": str(item.get("thumb") or item.get("grandparentThumb") or ""),
                "observed_at": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            }
        )
    return sessions



def cache_plex_artwork(
    server: PlexServer,
    token: str,
    thumb: str,
    cache_dir: Path,
) -> str:
    """Cache Plex artwork and return an opaque local filename."""

    if not token or not thumb:
        return ""

    parsed = urllib.parse.urlsplit(str(thumb))
    artwork_path = parsed.path

    if (
        parsed.scheme
        or parsed.netloc
        or not artwork_path.startswith("/")
        or artwork_path.startswith("//")
        or "\\" in artwork_path
        or ".." in artwork_path.split("/")
    ):
        return ""

    digest = hashlib.sha256(
        (
            server.name
            + "\0"
            + artwork_path
        ).encode("utf-8")
    ).hexdigest()

    supported_extensions = {
        ".jpg",
        ".jpeg",
        ".png",
        ".webp",
        ".gif",
        ".avif",
    }

    try:
        cache_dir.mkdir(
            parents=True,
            exist_ok=True,
        )
        cache_dir.chmod(0o750)
    except OSError as exc:
        LOG.warning(
            "Plex artwork cache directory failed "
            "server=%s error=%s: %s",
            server.name,
            type(exc).__name__,
            str(exc)[:160],
        )
        return ""

    for existing in cache_dir.glob(
        f"{digest}.*"
    ):
        try:
            if (
                existing.suffix.lower()
                in supported_extensions
                and existing.is_file()
                and existing.stat().st_size > 0
            ):
                existing.touch()
                return existing.name
        except OSError as exc:
            LOG.warning(
                "Plex cached artwork access failed "
                "server=%s file=%s error=%s: %s",
                server.name,
                existing.name,
                type(exc).__name__,
                str(exc)[:160],
            )
            continue

    endpoint = (
        server.url.rstrip("/")
        + artwork_path
    )

    context = None

    if endpoint.lower().startswith("https://"):
        context = ssl.create_default_context()

        if not server.tls_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

    request = urllib.request.Request(
        endpoint,
        headers={
            "Accept": (
                "image/avif,image/webp,"
                "image/png,image/jpeg,image/*"
            ),
            "X-Plex-Token": token,
            "X-Plex-Product": "EdgeWatch",
            "X-Plex-Version": "0.5.4",
            "User-Agent": "EdgeWatch/0.5.4",
            "Connection": "close",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(  # nosec B310
            request,
            timeout=min(
                10.0,
                max(
                    2.0,
                    float(server.timeout_seconds),
                ),
            ),
            context=context,
        ) as response:
            content_type = (
                response.headers.get_content_type()
                or ""
            ).lower()

            content = response.read(
                12_000_001
            )

        if (
            not content
            or len(content) > 12_000_000
        ):
            LOG.warning(
                "Plex artwork content rejected "
                "server=%s bytes=%s",
                server.name,
                len(content),
            )
            return ""

        extensions = {
            "image/jpeg": ".jpg",
            "image/jpg": ".jpg",
            "image/png": ".png",
            "image/webp": ".webp",
            "image/gif": ".gif",
            "image/avif": ".avif",
        }

        extension = extensions.get(
            content_type,
            "",
        )

        if not extension:
            if content.startswith(b"\xff\xd8\xff"):
                extension = ".jpg"
            elif content.startswith(b"\x89PNG\r\n\x1a\n"):
                extension = ".png"
            elif (
                content.startswith(b"RIFF")
                and content[8:12] == b"WEBP"
            ):
                extension = ".webp"
            elif content.startswith(
                (b"GIF87a", b"GIF89a")
            ):
                extension = ".gif"
            else:
                LOG.warning(
                    "Plex artwork type unsupported "
                    "server=%s content_type=%s",
                    server.name,
                    content_type,
                )
                return ""

        target = cache_dir / (
            digest + extension
        )
        temporary = cache_dir / (
            f".{digest}.{os.getpid()}.tmp"
        )

        with temporary.open("wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

        temporary.chmod(0o640)
        os.replace(
            temporary,
            target,
        )

        return target.name

    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        OSError,
        ValueError,
    ) as exc:
        LOG.warning(
            "Plex artwork cache failed "
            "server=%s path=%s error=%s: %s",
            server.name,
            artwork_path,
            type(exc).__name__,
            str(exc)[:180],
        )

        with suppress(
            OSError,
            UnboundLocalError,
        ):
            temporary.unlink(
                missing_ok=True
            )

        return ""


def fetch_plex_sessions(server: PlexServer, token: str) -> dict[str, object]:
    if not token:
        return {
            "name": server.name,
            "url": server.url,
            "ok": False,
            "configured": False,
            "status": "token missing",
            "latency_ms": None,
            "sessions": [],
        }

    context = None
    if server.url.lower().startswith("https://"):
        context = ssl.create_default_context()
        if not server.tls_verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

    endpoint = f"{server.url}/status/sessions"
    request = urllib.request.Request(
        endpoint,
        headers={
            "Accept": "application/json",
            "X-Plex-Token": token,
            "X-Plex-Product": "EdgeWatch",
            "X-Plex-Version": "0.5.4",
            "User-Agent": "EdgeWatch/0.5.4",
            "Connection": "close",
        },
        method="GET",
    )
    started = time.monotonic()
    try:
        # Plex server URLs are validated as HTTP or HTTPS during configuration loading.
        with urllib.request.urlopen(  # nosec B310
            request, timeout=server.timeout_seconds, context=context
        ) as response:
            raw = response.read(2_000_000)
            status = int(response.status)
        payload = json.loads(raw.decode("utf-8", errors="replace"))
        if not isinstance(payload, dict):
            raise ValueError("Plex returned an unexpected payload")
        sessions = parse_sessions(payload, server.name)
        return {
            "name": server.name,
            "url": server.url,
            "ok": 200 <= status < 300,
            "configured": True,
            "status": status,
            "latency_ms": round((time.monotonic() - started) * 1000),
            "sessions": sessions,
        }
    except urllib.error.HTTPError as exc:
        return {
            "name": server.name,
            "url": server.url,
            "ok": False,
            "configured": True,
            "status": int(exc.code),
            "latency_ms": round((time.monotonic() - started) * 1000),
            "detail": str(exc.reason)[:160],
            "sessions": [],
        }
    except Exception as exc:
        return {
            "name": server.name,
            "url": server.url,
            "ok": False,
            "configured": True,
            "status": "failed",
            "latency_ms": None,
            "detail": str(exc)[:180],
            "sessions": [],
        }


def summarize_plex(servers: list[dict[str, object]]) -> dict[str, object]:
    sessions = [session for server in servers for session in server.get("sessions", []) if isinstance(session, dict)]
    direct_play = sum(1 for item in sessions if item.get("mode") == "Direct Play")
    direct_stream = sum(1 for item in sessions if item.get("mode") == "Direct Stream")
    transcode = sum(1 for item in sessions if item.get("mode") == "Transcode")
    bandwidth = sum(_int(item.get("bandwidth_kbps")) for item in sessions)
    return {
        "servers": servers,
        "sessions": sessions,
        "active_streams": len(sessions),
        "direct_play": direct_play,
        "direct_stream": direct_stream,
        "transcode": transcode,
        "bandwidth_kbps": bandwidth,
        "healthy_servers": sum(1 for server in servers if server.get("ok")),
        "server_count": len(servers),
    }
