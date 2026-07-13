#!/usr/bin/env python3

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess  # nosec B404
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 on Ubuntu 22.04
    import tomli as tomllib

SAFE_ENV_KEYS = {
    "OAUTH2_PROXY_PROVIDER": "provider",
    "OAUTH2_PROXY_PROVIDER_DISPLAY_NAME": "provider_display_name",
    "OAUTH2_PROXY_OIDC_ISSUER_URL": "oidc_issuer_url",
    "OAUTH2_PROXY_AZURE_TENANT": "azure_tenant",
    "OAUTH2_PROXY_CLIENT_ID": "client_id",
    "OAUTH2_PROXY_COOKIE_EXPIRE": "cookie_expire",
    "OAUTH2_PROXY_COOKIE_REFRESH": "cookie_refresh",
}

SAFE_FLAG_KEYS = {
    "provider",
    "provider-display-name",
    "oidc-issuer-url",
    "azure-tenant",
    "client-id",
    "cookie-expire",
    "cookie-refresh",
}

COMMON_CONFIG_PATHS = (
    Path("/etc/oauth2-proxy.cfg"),
    Path("/etc/oauth2-proxy/oauth2-proxy.cfg"),
    Path("/etc/oauth2-proxy/oauth2-proxy.toml"),
    Path("/etc/oauth2-proxy/config.cfg"),
)


def clean(value: object, limit: int = 240) -> str:
    return str(value or "").strip()[:limit]


def toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def parse_duration_seconds(value: object) -> int | None:
    text = clean(value, 80).lower().replace(" ", "")
    if not text:
        return None
    if text in {"0", "0s", "off", "false", "disabled", "none"}:
        return 0
    if text.isdigit():
        return int(text)

    pattern = re.compile(r"(\d+(?:\.\d+)?)(ms|s|m|h|d|w)")
    position = 0
    total = 0.0
    units = {
        "ms": 0.001,
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
        "w": 604800,
    }
    for match in pattern.finditer(text):
        if match.start() != position:
            return None
        total += float(match.group(1)) * units[match.group(2)]
        position = match.end()
    if position != len(text):
        return None
    return max(0, round(total))


def human_duration(value: object, *, recurring: bool = False) -> str:
    seconds = parse_duration_seconds(value)
    if seconds is None:
        return ""
    if seconds == 0:
        return "Disabled"

    units = (
        (604800, "week"),
        (86400, "day"),
        (3600, "hour"),
        (60, "minute"),
        (1, "second"),
    )
    parts: list[str] = []
    remaining = seconds
    for unit_seconds, label in units:
        count, remaining = divmod(remaining, unit_seconds)
        if count:
            parts.append(f"{count} {label}{'' if count == 1 else 's'}")
        if len(parts) == 2:
            break
    rendered = " ".join(parts) if parts else f"{seconds} seconds"
    return f"Every {rendered}" if recurring else rendered


def tenant_from_issuer(issuer: object) -> tuple[str, str]:
    value = clean(issuer, 500)
    if not value:
        return "", ""
    parsed = urlsplit(value)
    host = (parsed.hostname or "").lower()
    segments = [segment for segment in parsed.path.split("/") if segment]
    tenant = segments[0] if segments else ""
    if host not in {"login.microsoftonline.com", "login.windows.net", "sts.windows.net"}:
        return "", ""
    if not tenant or tenant.lower() in {"common", "organizations", "consumers"}:
        return "", tenant
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        tenant,
    ):
        return tenant.lower(), ""
    return "", tenant


def flatten_toml(raw: dict[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    for key in (
        "provider",
        "provider_display_name",
        "oidc_issuer_url",
        "azure_tenant",
        "client_id",
        "cookie_expire",
        "cookie_refresh",
    ):
        if key in raw:
            values[key] = clean(raw[key], 500)
    return values


def parse_config_file(path: Path) -> dict[str, str]:
    try:
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    return flatten_toml(raw)


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        key = key.strip()
        target = SAFE_ENV_KEYS.get(key)
        if not target:
            continue
        try:
            parsed = shlex.split(raw_value, posix=True)
            value = parsed[0] if parsed else ""
        except ValueError:
            value = raw_value.strip().strip('"\'')
        values[target] = clean(value, 500)
    return values


def parse_safe_environment_lines(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("Environment="):
            continue
        raw_value = stripped.split("=", 1)[1].strip()
        try:
            assignments = shlex.split(raw_value, posix=True)
        except ValueError:
            assignments = [raw_value.strip('"\'')]
        for assignment in assignments:
            if "=" not in assignment:
                continue
            key, value = assignment.split("=", 1)
            target = SAFE_ENV_KEYS.get(key.strip())
            if target:
                values[target] = clean(value, 500)
    return values


def parse_safe_flags(command: str) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return values
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if not token.startswith("--"):
            index += 1
            continue
        key_value = token[2:].split("=", 1)
        key = key_value[0]
        if key not in SAFE_FLAG_KEYS:
            index += 1
            continue
        if len(key_value) == 2:
            value = key_value[1]
        elif index + 1 < len(tokens) and not tokens[index + 1].startswith("--"):
            index += 1
            value = tokens[index]
        else:
            value = "true"
        values[key.replace("-", "_")] = clean(value, 500)
        index += 1
    return values


def systemd_text() -> str:
    commands = (
        ["systemctl", "cat", "oauth2-proxy.service"],
        ["systemctl", "show", "oauth2-proxy.service", "--property=ExecStart", "--value"],
    )
    chunks: list[str] = []
    for command in commands:
        try:
            result = subprocess.run(  # nosec B603
                command,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0 and result.stdout.strip():
            chunks.append(result.stdout)
    return "\n".join(chunks)


def config_paths_from_systemd(text: str) -> list[Path]:
    paths: list[Path] = []
    for match in re.finditer(r"--config(?:=|\s+)([^\s\"']+|\"[^\"]+\"|'[^']+')", text):
        candidate = match.group(1).strip('"\'')
        if candidate:
            paths.append(Path(candidate))
    for match in re.finditer(r"OAUTH2_PROXY_CONFIG=([^\s\"']+|\"[^\"]+\"|'[^']+')", text):
        candidate = match.group(1).strip('"\'')
        if candidate:
            paths.append(Path(candidate))
    return paths


def env_paths_from_systemd(text: str) -> list[Path]:
    paths: list[Path] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("EnvironmentFile="):
            continue
        raw_value = stripped.split("=", 1)[1].strip().lstrip("-")
        try:
            tokens = shlex.split(raw_value, posix=True)
        except ValueError:
            tokens = [raw_value.strip('"\'')]
        for token in tokens:
            if token:
                paths.append(Path(token))
    return paths


def unique_existing(paths: Iterable[Path]) -> list[Path]:
    seen: set[str] = set()
    existing: list[Path] = []
    for path in paths:
        value = str(path)
        if not value or value in seen:
            continue
        seen.add(value)
        if path.is_file():
            existing.append(path)
    return existing


def discover(explicit: Path | None = None) -> tuple[dict[str, str], list[str]]:
    unit = systemd_text()
    candidate_paths: list[Path] = []
    if explicit:
        candidate_paths.append(explicit)
    env_config = os.environ.get("OAUTH2_PROXY_CONFIG", "").strip()
    if env_config:
        candidate_paths.append(Path(env_config))
    candidate_paths.extend(config_paths_from_systemd(unit))
    candidate_paths.extend(COMMON_CONFIG_PATHS)

    values: dict[str, str] = {}
    sources: list[str] = []
    for path in unique_existing(candidate_paths):
        found = parse_config_file(path)
        if found:
            values.update(found)
            sources.append(str(path))
            break

    for env_path in unique_existing(env_paths_from_systemd(unit)):
        found = parse_env_file(env_path)
        if found:
            values.update(found)
            sources.append(str(env_path))

    service_values = parse_safe_environment_lines(unit)
    service_values.update(parse_safe_flags(unit))
    if service_values:
        values.update(service_values)
        sources.append("oauth2-proxy.service")

    for env_key, target in SAFE_ENV_KEYS.items():
        if env_key in os.environ:
            values[target] = clean(os.environ[env_key], 500)
            sources.append("process environment")

    return values, list(dict.fromkeys(sources))


def identity_section(values: dict[str, str]) -> dict[str, str]:
    issuer = values.get("oidc_issuer_url", "")
    tenant_id, directory_name = tenant_from_issuer(issuer)
    azure_tenant = clean(values.get("azure_tenant", ""), 200)
    if not tenant_id and re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
        r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        azure_tenant,
    ):
        tenant_id = azure_tenant.lower()
    elif not directory_name and azure_tenant.lower() not in {
        "",
        "common",
        "organizations",
        "consumers",
    }:
        directory_name = azure_tenant
    provider = values.get("provider_display_name", "")
    if not provider:
        host = (urlsplit(issuer).hostname or "").lower()
        configured_provider = values.get("provider", "").lower()
        provider = "Microsoft Entra ID" if (
            host in {
                "login.microsoftonline.com",
                "login.windows.net",
                "sts.windows.net",
            }
            or configured_provider in {"azure", "entra-id", "microsoft-entra-id"}
        ) else values.get("provider", "") or "Microsoft Entra ID"

    return {
        "provider": clean(provider, 120),
        "directory_name": clean(directory_name, 200),
        "tenant_id": clean(tenant_id, 200),
        "application_name": "EdgeWatch",
        "client_id": clean(values.get("client_id", ""), 200),
        "access_label": "Assigned enterprise application user",
        "session_lifetime": human_duration(values.get("cookie_expire", "")),
        "session_refresh": human_duration(
            values.get("cookie_refresh", ""),
            recurring=True,
        ),
    }


def render_section(identity: dict[str, str]) -> str:
    lines = [
        "",
        "# Safe, non-secret authentication metadata shown in the account drawer.",
        "# The installer discovered these values from oauth2-proxy when available.",
        "[identity]",
    ]
    for key in (
        "provider",
        "directory_name",
        "tenant_id",
        "application_name",
        "client_id",
        "access_label",
        "session_lifetime",
        "session_refresh",
    ):
        lines.append(f"{key} = {toml_string(identity.get(key, ''))}")
    return "\n".join(lines) + "\n"


IDENTITY_KEYS = (
    "provider",
    "directory_name",
    "tenant_id",
    "application_name",
    "client_id",
    "access_label",
    "session_lifetime",
    "session_refresh",
)


def fill_identity_section(text: str, current: dict[str, Any], discovered: dict[str, str]) -> tuple[str, bool]:
    section_match = re.search(
        r"(?ms)^\[identity\]\s*$.*?(?=^\[[^\n]+\]\s*$|\Z)",
        text,
    )
    if section_match is None:
        return text + render_section(discovered), True

    section = section_match.group(0)
    changed = False
    for key in IDENTITY_KEYS:
        existing = clean(current.get(key, ""), 500)
        value = clean(discovered.get(key, ""), 500)
        if existing or not value:
            continue
        assignment = re.compile(rf"(?m)^(\s*{re.escape(key)}\s*=\s*).*$")
        replacement = rf"\g<1>{toml_string(value)}"
        if assignment.search(section):
            section = assignment.sub(replacement, section, count=1)
        else:
            section = section.rstrip() + f"\n{key} = {toml_string(value)}\n"
        changed = True

    if not changed:
        return text, False
    return text[: section_match.start()] + section + text[section_match.end() :], True


def migrate(config_path: Path, explicit: Path | None = None) -> tuple[bool, list[str]]:
    original = config_path.read_text(encoding="utf-8")
    raw = tomllib.loads(original)
    values, sources = discover(explicit)
    identity = identity_section(values)

    if "identity" not in raw:
        updated = original + render_section(identity)
        changed = True
    else:
        updated, changed = fill_identity_section(
            original,
            raw.get("identity", {}),
            identity,
        )

    if changed:
        config_path.write_text(updated, encoding="utf-8")
    return changed, sources if changed else []


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Add safe oauth2-proxy identity metadata to EdgeWatch config.",
    )
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--oauth2-config", type=Path)
    args = parser.parse_args()

    try:
        changed, sources = migrate(args.config, args.oauth2_config)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"identity metadata migration failed: {exc}", file=sys.stderr)
        return 1

    if not changed:
        print("Existing [identity] configuration preserved.")
    elif sources:
        print("Added or updated safe identity metadata from " + ", ".join(sources) + ".")
    else:
        print(
            "Updated the [identity] section. oauth2-proxy identifiers were not "
            "auto-detected; optional fields remain blank."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
