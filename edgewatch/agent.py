from __future__ import annotations

import argparse
import logging
import os
import signal
import time

from .collector import Collector, event_from_insight
from .config import load_config, load_secrets
from .control import ControlStorage
from .notifications import NotificationManager
from .storage import Storage, atomic_write_json

LOG = logging.getLogger("edgewatch.agent")
STOP = False


def _handle_stop(_signum: int, _frame: object) -> None:
    global STOP
    STOP = True


def configure_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("EDGEWATCH_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _merged_events(
    storage: Storage,
    control: ControlStorage,
    limit: int,
) -> list[dict[str, object]]:
    events = storage.recent_events(limit) + control.recent_events(limit)
    events.sort(
        key=lambda item: int(item.get("ts") or 0),
        reverse=True,
    )
    return events[:limit]


def _attach_acknowledgements(
    snapshot: dict[str, object],
    controls: dict[str, dict[str, object]],
) -> None:
    posture = snapshot.get("posture")
    if not isinstance(posture, dict):
        return
    insights = posture.get("insights")
    if not isinstance(insights, list):
        return

    acknowledged_rows: list[dict[str, object]] = []
    for insight in insights:
        if not isinstance(insight, dict):
            continue
        fingerprint = str(insight.get("fingerprint") or "")
        control = controls.get(fingerprint) or {}
        active = bool(control.get("active"))
        insight["acknowledged"] = active
        if not active:
            insight.pop("acknowledgement", None)
            continue

        acknowledgement = {
            "acknowledged_at": control.get("acknowledged_at"),
            "acknowledged_by": control.get("acknowledged_by"),
            "acknowledged_severity": control.get("acknowledged_severity"),
            "current_severity": control.get("current_severity"),
        }
        insight["acknowledgement"] = acknowledgement
        acknowledged_rows.append(
            {
                "fingerprint": fingerprint,
                "title": insight.get("title"),
                "category": insight.get("category"),
                "severity": insight.get("severity"),
                "score": insight.get("score"),
                "detail": insight.get("detail"),
                "remediation": insight.get("remediation"),
                **acknowledgement,
            }
        )

    posture["acknowledged_findings"] = len(acknowledged_rows)
    snapshot["acknowledged_findings"] = acknowledged_rows


def run(config_path: str, once: bool = False) -> int:
    config = load_config(config_path)
    secrets = load_secrets(config.secrets_path)
    config.data_dir.mkdir(parents=True, exist_ok=True)
    config.runtime_dir.mkdir(parents=True, exist_ok=True)

    storage = Storage(config.database_path)
    storage.initialize()
    control = ControlStorage(config.data_dir / "control" / "edgewatch-control.db")
    control.initialize()
    collector = Collector(config, secrets=secrets)
    notifier = NotificationManager(config.notifications, secrets.ntfy, storage)
    prune_at = 0.0
    last_history_at = 0.0
    last_evaluation_at = 0.0
    last_evaluation_signature = ""
    traffic_batches: dict[tuple[str, str], list[int]] = {}
    cached_events = _merged_events(storage, control, 75)
    notification_summary = storage.notification_summary()
    monthly_cache_month = ""
    monthly_persisted = {"rx_bytes": 0, "tx_bytes": 0}

    while not STOP:
        started = time.monotonic()
        try:
            snapshot, sample = collector.collect()
            day = str(sample["day"])
            interface = str(sample["interface"])
            batch = traffic_batches.setdefault((day, interface), [0, 0])
            batch[0] += int(sample["rx_bytes"])
            batch[1] += int(sample["tx_bytes"])

            history_due = once or started - last_history_at >= config.history_interval_seconds
            if history_due:
                storage.add_sample(sample)
                for (batch_day, batch_interface), values in traffic_batches.items():
                    storage.add_traffic(batch_day, batch_interface, values[0], values[1])
                traffic_batches.clear()
                last_history_at = started

            month = str(snapshot["network"]["month"])
            if monthly_cache_month != month or history_due:
                monthly_cache_month = month
                monthly_persisted = storage.monthly_traffic(month, interface)
            pending_rx = sum(values[0] for (batch_day, batch_interface), values in traffic_batches.items() if batch_day.startswith(month) and batch_interface == interface)
            pending_tx = sum(values[1] for (batch_day, batch_interface), values in traffic_batches.items() if batch_day.startswith(month) and batch_interface == interface)
            monthly_rx = monthly_persisted["rx_bytes"] + pending_rx
            monthly_tx = monthly_persisted["tx_bytes"] + pending_tx

            # Preserve EdgeWatch's locally observed counters for diagnostics.
            snapshot["network"]["monthly_rx_bytes"] = monthly_rx
            snapshot["network"]["monthly_tx_bytes"] = monthly_tx
            snapshot["network"]["monthly_local_rx_bytes"] = monthly_rx
            snapshot["network"]["monthly_local_tx_bytes"] = monthly_tx

            transfer_source = str(
                snapshot["network"].get("monthly_transfer_source")
                or "local_estimate"
            )

            if transfer_source == "linode_account_api":
                used_gb = float(
                    snapshot["network"].get(
                        "monthly_transfer_used_gb"
                    )
                    or 0.0
                )
                quota_gb = float(
                    snapshot["network"].get(
                        "monthly_transfer_quota_gb"
                    )
                    or 0.0
                )
                snapshot["network"]["monthly_egress_percent"] = (
                    round(used_gb * 100 / quota_gb, 2)
                    if quota_gb > 0
                    else 0.0
                )
            else:
                limit = int(
                    snapshot["network"][
                        "monthly_transfer_limit_bytes"
                    ]
                )
                snapshot["network"]["monthly_transfer_used_bytes"] = (
                    monthly_tx
                )
                snapshot["network"]["monthly_egress_percent"] = (
                    round(monthly_tx * 100 / limit, 2)
                    if limit > 0
                    else 0.0
                )

            now_epoch = int(sample["ts"])
            insights = snapshot["posture"]["insights"]
            controls_before = control.controls()
            insight_signature = sorted(
                f"{item.get('fingerprint')}:{item.get('severity')}:{item.get('score')}"
                for item in insights
                if item.get("fingerprint")
            )
            control_signature = sorted(
                f"{fingerprint}:{int(bool(item.get('active')))}:"
                f"{int(item.get('resumed_at') or 0)}:{item.get('current_severity')}"
                for fingerprint, item in controls_before.items()
            )
            evaluation_signature = "|".join(insight_signature + control_signature)
            evaluation_due = (
                once
                or evaluation_signature != last_evaluation_signature
                or started - last_evaluation_at >= min(60, config.security_interval_seconds)
            )
            notification_results: list[dict[str, object]] = []
            if evaluation_due:
                # Use the pre-reconciliation state so a muted finding does not
                # emit a recovery notification in the same cycle that clears it.
                notification_results = notifier.process(
                    insights,
                    now_epoch,
                    controls=controls_before,
                )
                control.reconcile(insights, now_epoch)
                controls_after = control.controls()
                acknowledged = {
                    fingerprint
                    for fingerprint, item in controls_after.items()
                    if bool(item.get("active"))
                }
                for insight in insights:
                    if (
                        int(insight.get("score", 0)) > 0
                        and str(insight.get("fingerprint") or "") not in acknowledged
                    ):
                        storage.add_event(event_from_insight(insight, now_epoch))
                notification_summary = storage.notification_summary()
                last_evaluation_signature = evaluation_signature
                last_evaluation_at = started
            else:
                controls_after = controls_before

            _attach_acknowledgements(snapshot, controls_after)
            cached_events = _merged_events(storage, control, 75)
            snapshot["notifications"]["summary"] = notification_summary
            snapshot["notifications"]["last_cycle"] = notification_results
            snapshot["events"] = cached_events
            atomic_write_json(config.snapshot_path, snapshot)

            if time.monotonic() >= prune_at:
                storage.prune(config.retention_days)
                control.prune(config.retention_days)
                prune_at = time.monotonic() + 21600

            LOG.info(
                "sample collected risk=%s rx=%s tx=%s streams=%s peers=%s",
                snapshot["posture"]["risk_score"],
                snapshot["network"]["rx_rate"],
                snapshot["network"]["tx_rate"],
                snapshot["plex"]["active_streams"],
                snapshot["network"]["connections"]["public_peer_count"],
            )
        except Exception:
            LOG.exception("collector cycle failed")

        if once:
            break
        sleep_for = max(0.1, config.sample_interval_seconds - (time.monotonic() - started))
        end = time.monotonic() + sleep_for
        while not STOP and time.monotonic() < end:
            time.sleep(min(0.25, end - time.monotonic()))

    collector.geoip.close()
    return 0


def test_notification(config_path: str) -> int:
    config = load_config(config_path)
    secrets = load_secrets(config.secrets_path)
    storage = Storage(config.database_path)
    storage.initialize()
    notifier = NotificationManager(config.notifications, secrets.ntfy, storage)
    ok, detail = notifier.test()
    storage.add_notification_log(int(time.time()), "ntfy", "notification-test", ok, detail)
    print(f"{'SUCCESS' if ok else 'FAILED'}: {detail}")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="EdgeWatch privileged metrics collector")
    parser.add_argument("--config", default="/etc/edgewatch/config.toml")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--test-notification", action="store_true")
    args = parser.parse_args(argv)

    configure_logging()
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)
    if args.test_notification:
        return test_notification(args.config)
    return run(args.config, once=args.once)


if __name__ == "__main__":
    raise SystemExit(main())
