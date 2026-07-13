from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import maxminddb

from .config import GeoIPConfig

LOG = logging.getLogger("edgewatch.geoip")


class GeoIPResolver:
    """Local-only MaxMind DB lookups with no third-party query leakage."""

    def __init__(self, config: GeoIPConfig):
        self.config = config
        self._city_reader: Any = None
        self._asn_reader: Any = None
        self._city_mtime: float | None = None
        self._asn_mtime: float | None = None
        self._cache: dict[str, dict[str, object]] = {}
        self._last_refresh = 0.0
        self._refresh_readers(force=True)

    @staticmethod
    def _mtime(path: Path) -> float | None:
        try:
            return path.stat().st_mtime
        except OSError:
            return None

    @staticmethod
    def _close(reader: Any) -> None:
        try:
            if reader is not None:
                reader.close()
        except Exception as exc:
            LOG.debug("GeoIP reader close failed: %s", exc)

    def _open(self, path: Path) -> Any:
        try:
            return maxminddb.open_database(str(path))
        except Exception as exc:
            LOG.warning("GeoIP database unavailable path=%s error=%s", path, exc)
            return None

    def _refresh_readers(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_refresh < 60:
            return
        self._last_refresh = now

        city_mtime = self._mtime(self.config.city_database_path)
        asn_mtime = self._mtime(self.config.asn_database_path)
        if force or city_mtime != self._city_mtime:
            self._close(self._city_reader)
            self._city_reader = self._open(self.config.city_database_path) if city_mtime else None
            self._city_mtime = city_mtime
            self._cache.clear()
        if force or asn_mtime != self._asn_mtime:
            self._close(self._asn_reader)
            self._asn_reader = self._open(self.config.asn_database_path) if asn_mtime else None
            self._asn_mtime = asn_mtime
            self._cache.clear()

    @staticmethod
    def _english_name(record: dict[str, Any] | None) -> str:
        if not record:
            return ""
        names = record.get("names") or {}
        return str(names.get("en") or "")

    def lookup(self, ip: str) -> dict[str, object]:
        self._refresh_readers()
        if ip in self._cache:
            return dict(self._cache[ip])

        result: dict[str, object] = {
            "located": False,
            "country_code": "",
            "country": "",
            "region": "",
            "city": "",
            "latitude": None,
            "longitude": None,
            "accuracy_radius_km": None,
            "asn": None,
            "organization": "",
        }

        if self._city_reader is not None:
            try:
                record = self._city_reader.get(ip) or {}
                country = record.get("country") or record.get("registered_country") or {}
                subdivisions = record.get("subdivisions") or []
                location = record.get("location") or {}
                result.update(
                    {
                        "country_code": str(country.get("iso_code") or ""),
                        "country": self._english_name(country),
                        "region": self._english_name(subdivisions[0]) if subdivisions else "",
                        "city": self._english_name(record.get("city") or {}),
                        "latitude": location.get("latitude"),
                        "longitude": location.get("longitude"),
                        "accuracy_radius_km": location.get("accuracy_radius"),
                    }
                )
                result["located"] = result["latitude"] is not None and result["longitude"] is not None
            except (ValueError, OSError, maxminddb.errors.InvalidDatabaseError) as exc:
                LOG.debug("GeoIP city lookup failed ip=%s error=%s", ip, exc)

        if self._asn_reader is not None:
            try:
                record = self._asn_reader.get(ip) or {}
                result["asn"] = record.get("autonomous_system_number")
                result["organization"] = str(record.get("autonomous_system_organization") or "")
            except (ValueError, OSError, maxminddb.errors.InvalidDatabaseError) as exc:
                LOG.debug("GeoIP ASN lookup failed ip=%s error=%s", ip, exc)

        self._cache[ip] = dict(result)
        if len(self._cache) > 4096:
            self._cache.clear()
        return result

    def status(self) -> dict[str, object]:
        self._refresh_readers()
        paths = [self.config.city_database_path, self.config.asn_database_path]
        files: list[dict[str, object]] = []
        now = datetime.now(timezone.utc)
        for path in paths:
            try:
                stat = path.stat()
                modified = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
                age_days = max(0.0, (now - modified).total_seconds() / 86400)
                files.append(
                    {
                        "path": str(path),
                        "available": True,
                        "modified_at": modified.isoformat(),
                        "age_days": round(age_days, 1),
                        "stale": age_days > self.config.warn_age_days,
                    }
                )
            except OSError:
                files.append(
                    {
                        "path": str(path),
                        "available": False,
                        "modified_at": None,
                        "age_days": None,
                        "stale": False,
                    }
                )
        return {
            "enabled": self._city_reader is not None,
            "city_available": self._city_reader is not None,
            "asn_available": self._asn_reader is not None,
            "local_lookup": True,
            "files": files,
            "warning": "IP geolocation is approximate and must not be treated as a physical address.",
        }

    def close(self) -> None:
        self._close(self._city_reader)
        self._close(self._asn_reader)
        self._city_reader = None
        self._asn_reader = None
