from __future__ import annotations

import argparse
import os

import uvicorn

from .config import load_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the EdgeWatch web dashboard")
    parser.add_argument("--config", default=os.environ.get("EDGEWATCH_CONFIG", "/etc/edgewatch/config.toml"))
    args = parser.parse_args(argv)
    config = load_config(args.config)
    os.environ["EDGEWATCH_CONFIG"] = args.config

    uvicorn.run(
        "edgewatch.web:app_factory",
        factory=True,
        host=config.bind_host,
        port=config.bind_port,
        workers=1,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
        access_log=False,
        server_header=False,
        date_header=True,
        log_level=os.environ.get("EDGEWATCH_LOG_LEVEL", "info").lower(),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
