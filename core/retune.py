"""
Retune engine — compares current baseline against the one used at provision time.
If drift exceeds threshold, updates detector thresholds in-place via PATCH /v2/detector.
No new detectors created — only SignalFlow text and rule thresholds are updated.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .baseline_learner import ServiceBaseline
from .state import ProvisionerState, DetectorRecord

logger = logging.getLogger(__name__)

# Minimum relative change in mean or stddev to trigger a retune
RETUNE_DRIFT_THRESHOLD = 0.20   # 20%


@dataclass
class RetuneResult:
    service: str
    environment: str
    detector_id: str
    detector_name: str
    action: str          # "updated" | "skipped" | "failed"
    reason: str = ""


def baseline_hash(baseline: ServiceBaseline) -> str:
    """Stable hash of the baseline values used to decide if retune is needed."""
    parts = [
        str(round(baseline.latency_mean_ms or 0, 1)),
        str(round(baseline.latency_p99_ms or 0, 1)),
        str(round(baseline.latency_stddev_ms or 0, 1)),
        str(round(baseline.error_rate_pct or 0, 3)),
        str(baseline.sample_count),
    ]
    return hashlib.md5("|".join(parts).encode()).hexdigest()[:12]


def signalflow_hash(signalflow_text: str) -> str:
    return hashlib.md5(signalflow_text.strip().encode()).hexdigest()[:12]


def _drift_pct(old: float | None, new: float | None) -> float:
    """Return relative change between old and new values."""
    if old is None or new is None or old == 0:
        return 0.0
    return abs(new - old) / abs(old)


def _api_get(api_base: str, token: str, detector_id: str) -> dict:
    url = f"{api_base}/v2/detector/{detector_id}"
    req = urllib.request.Request(url, headers={"X-SF-Token": token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:300].decode()}")


def _api_patch(api_base: str, token: str, detector_id: str, body: dict) -> dict:
    url = f"{api_base}/v2/detector/{detector_id}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"X-SF-Token": token, "Content-Type": "application/json"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:500].decode()}")


def _replace_threshold(text: str, old_val: float, new_val: float) -> str:
    """Replace a numeric threshold in SignalFlow using word-boundary regex to avoid partial matches.

    Handles both integer-formatted floats (200) and decimal-formatted floats (200.0)
    that may appear in SignalFlow text depending on how thresholds were originally written.
    """
    new_s = str(new_val)
    # Build candidate string representations of old_val to match:
    # 200.0 → try "200.0" and "200"; 200.5 → try "200.5" only
    candidates = [str(old_val)]
    if old_val == int(old_val):
        candidates.append(str(int(old_val)))

    for old_s in candidates:
        if old_s == new_s:
            continue
        pattern = r'(?<![0-9\.])' + re.escape(old_s) + r'(?![0-9\.])'
        new_text = re.sub(pattern, new_s, text)
        if new_text != text:
            return new_text
    return text


def _rebuild_signalflow(old_signalflow: str, old_baseline: dict, new_baseline: ServiceBaseline) -> str | None:
    """
    Replace threshold values in existing SignalFlow text using the new baseline.
    Handles latency (mean ± N*stddev) and error rate thresholds.
    Returns updated SignalFlow or None if no change needed.
    """
    text = old_signalflow

    old_lat_mean = old_baseline.get("latency_mean_ms") or 0
    old_lat_std = old_baseline.get("latency_stddev_ms") or 0
    old_err_mean = old_baseline.get("error_rate_pct")
    old_err_std = old_baseline.get("error_rate_stddev_pct") or 0

    changed = False

    # ── Latency thresholds ────────────────────────────────────────────────────
    # Prefer p99/1.5×p99 if stored in snapshot (matches apm.py generation).
    # Fall back to mean+Nσ for detectors provisioned before p99 tracking.
    old_lat_p99 = old_baseline.get("latency_p99_ms")
    if old_lat_p99 and new_baseline.latency_p99_ms:
        p99_drift = _drift_pct(old_lat_p99, new_baseline.latency_p99_ms)
        if p99_drift >= RETUNE_DRIFT_THRESHOLD:
            old_warn = round(old_lat_p99, 1)
            old_anomaly = round(old_lat_p99 * 1.5, 1)
            new_warn = round(new_baseline.latency_p99_ms, 1)
            new_anomaly = round(new_baseline.latency_p99_ms * 1.5, 1)
            for old_t, new_t in [(old_warn, new_warn), (old_anomaly, new_anomaly)]:
                new_text = _replace_threshold(text, old_t, new_t)
                if new_text != text:
                    text = new_text
                    changed = True
    elif old_lat_mean and new_baseline.latency_mean_ms:
        mean_drift = _drift_pct(old_lat_mean, new_baseline.latency_mean_ms)
        std_drift = _drift_pct(old_lat_std, new_baseline.latency_stddev_ms or 0)

        if mean_drift >= RETUNE_DRIFT_THRESHOLD or std_drift >= RETUNE_DRIFT_THRESHOLD:
            for n_sigma in [2.0, 3.0]:
                old_t = round(old_lat_mean + n_sigma * old_lat_std, 1)
                new_t = round(
                    (new_baseline.latency_mean_ms or 0) + n_sigma * (new_baseline.latency_stddev_ms or 0),
                    1,
                )
                new_text = _replace_threshold(text, old_t, new_t)
                if new_text != text:
                    text = new_text
                    changed = True

    # ── Error rate thresholds ─────────────────────────────────────────────────
    # apm.py generates: warn=max(mean*2, 1.0), anomaly=max(mean*4, 5.0)
    if old_err_mean is not None and new_baseline.error_rate_pct is not None:
        err_drift = _drift_pct(old_err_mean, new_baseline.error_rate_pct)
        if err_drift >= RETUNE_DRIFT_THRESHOLD:
            old_warn = round(max(old_err_mean * 2, 1.0), 2)
            old_anomaly = round(max(old_err_mean * 4, 5.0), 2)
            new_warn = round(max(new_baseline.error_rate_pct * 2, 1.0), 2)
            new_anomaly = round(max(new_baseline.error_rate_pct * 4, 5.0), 2)
            for old_t, new_t in [(old_warn, new_warn), (old_anomaly, new_anomaly)]:
                new_text = _replace_threshold(text, old_t, new_t)
                if new_text != text:
                    text = new_text
                    changed = True

    return text if changed else None


def retune_service(
    realm: str,
    token: str,
    service: str,
    environment: str,
    new_baseline: ServiceBaseline,
    state: ProvisionerState,
    dry_run: bool = True,
    retune_interval_days: float = 7.0,
) -> list[RetuneResult]:
    """
    Compare current baseline to the one recorded at provision time.
    For each dynamic-threshold detector, patch the SignalFlow if drift > threshold.
    """
    api_base = f"https://api.{realm}.signalfx.com"
    results: list[RetuneResult] = []

    svc_state = state.get(service, environment)
    if not svc_state:
        logger.info("Retune: %s/%s not provisioned — skipping", environment, service)
        return results

    new_hash = baseline_hash(new_baseline)
    if not svc_state.needs_retune(new_hash, retune_interval_days):
        logger.info("Retune: %s/%s baseline unchanged — no retune needed", environment, service)
        return results

    logger.info("Retune: %s/%s baseline drifted — checking detectors", environment, service)

    old_baseline_snapshot = svc_state.baseline_snapshot

    updated_records: list[DetectorRecord] = []

    for record in svc_state.detector_records:
        if record.threshold_type != "dynamic":
            updated_records.append(record)
            results.append(RetuneResult(
                service=service, environment=environment,
                detector_id=record.detector_id,
                detector_name=record.detector_name,
                action="skipped",
                reason="fixed threshold — no retune needed",
            ))
            continue

        if record.detector_id == "dry-run":
            updated_records.append(record)
            continue

        try:
            # Fetch current detector from API
            current = _api_get(api_base, token, record.detector_id)
            current_signalflow = current.get("programText", "")

            new_signalflow = _rebuild_signalflow(
                current_signalflow,
                old_baseline_snapshot,
                new_baseline,
            )

            if not new_signalflow:
                updated_records.append(record)
                results.append(RetuneResult(
                    service=service, environment=environment,
                    detector_id=record.detector_id,
                    detector_name=record.detector_name,
                    action="skipped",
                    reason=f"drift below {RETUNE_DRIFT_THRESHOLD*100:.0f}% threshold",
                ))
                continue

            if dry_run:
                logger.info("[DRY RUN] Would retune detector: %s", record.detector_name)
                updated_records.append(record)
                results.append(RetuneResult(
                    service=service, environment=environment,
                    detector_id=record.detector_id,
                    detector_name=record.detector_name,
                    action="dry-run",
                    reason="would update SignalFlow thresholds",
                ))
                continue

            # Patch the detector
            patch_body = dict(current)
            patch_body["programText"] = new_signalflow
            _api_patch(api_base, token, record.detector_id, patch_body)

            new_record = DetectorRecord(
                detector_id=record.detector_id,
                detector_name=record.detector_name,
                provisioned_at=record.provisioned_at,
                signalflow_hash=signalflow_hash(new_signalflow),
                threshold_type=record.threshold_type,
                tags=record.tags,
            )
            updated_records.append(new_record)
            results.append(RetuneResult(
                service=service, environment=environment,
                detector_id=record.detector_id,
                detector_name=record.detector_name,
                action="updated",
                reason="SignalFlow thresholds updated to match new baseline",
            ))
            logger.info("Retune: updated detector %s (%s)", record.detector_name, record.detector_id)

        except RuntimeError as e:
            updated_records.append(record)
            results.append(RetuneResult(
                service=service, environment=environment,
                detector_id=record.detector_id,
                detector_name=record.detector_name,
                action="failed",
                reason=str(e),
            ))
            logger.error("Retune: failed to update %s: %s", record.detector_name, e)

    if not dry_run:
        new_snapshot = {
            "latency_mean_ms": new_baseline.latency_mean_ms,
            "latency_p95_ms": new_baseline.latency_p95_ms,
            "latency_p99_ms": new_baseline.latency_p99_ms,
            "latency_stddev_ms": new_baseline.latency_stddev_ms,
            "error_rate_pct": new_baseline.error_rate_pct,
            "error_rate_stddev_pct": new_baseline.error_rate_stddev_pct,
            "sample_count": new_baseline.sample_count,
        }
        state.record_retune(service, environment, new_hash, updated_records, baseline_snapshot=new_snapshot)

    return results


def audit_detector_effectiveness(
    realm: str,
    token: str,
    state: ProvisionerState,
    environment: str | None = None,
    lookback_hours: int = 168,
) -> list[dict]:
    """
    Query each provisioned detector's recent event history.
    Returns a list of dicts with keys:
      service, environment, detector_name, detector_id, events_per_day, verdict
    where verdict is 'noisy' (>10/day), 'silent' (0 events in window), or 'ok'.
    """
    api_base = f"https://api.{realm}.signalfx.com"
    report = []
    cutoff_ms = int((time.time() - lookback_hours * 3600) * 1000)

    for svc_state in state.all_services():
        if svc_state.archived:
            continue
        if environment and svc_state.environment != environment:
            continue
        for record in svc_state.detector_records:
            if record.detector_id in ("dry-run", "dry-run-create", "dry-run-update"):
                continue
            try:
                url = f"{api_base}/v2/detector/{record.detector_id}/events?offset=0&limit=1000"
                req = urllib.request.Request(
                    url, headers={"X-SF-Token": token, "Accept": "application/json"}
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode())
                events = data.get("results") or []
                recent = [e for e in events if (e.get("timestamp") or 0) >= cutoff_ms]
                epd = round(len(recent) / (lookback_hours / 24), 1)
                if epd > 10:
                    verdict = "noisy"
                elif len(recent) == 0:
                    verdict = "silent"
                else:
                    verdict = "ok"
                report.append({
                    "service": svc_state.service,
                    "environment": svc_state.environment,
                    "detector_name": record.detector_name,
                    "detector_id": record.detector_id,
                    "events_per_day": epd,
                    "verdict": verdict,
                })
            except Exception as e:
                logger.warning("Audit: failed to fetch events for %s (%s): %s",
                               record.detector_name, record.detector_id, e)
    return report


def format_retune_summary(results: list[RetuneResult], dry_run: bool) -> str:
    mode = "DRY RUN" if dry_run else "RETUNE"
    dry_run_items = [r for r in results if r.action == "dry-run"]
    updated = [r for r in results if r.action == "updated"]
    skipped = [r for r in results if r.action == "skipped"]
    failed = [r for r in results if r.action == "failed"]

    actioned = dry_run_items if dry_run else updated
    lines = [f"\n{mode} SUMMARY: {len(actioned)} {'would be updated' if dry_run else 'updated'}, "
             f"{len(skipped)} skipped, {len(failed)} failed"]

    if actioned:
        label = "WOULD UPDATE" if dry_run else "UPDATED"
        lines.append(f"\n{label} ({len(actioned)}):")
        for r in actioned:
            lines.append(f"  ✓ {r.detector_name}: {r.reason}")

    if failed:
        lines.append(f"\nFAILED ({len(failed)}):")
        for r in failed:
            lines.append(f"  ✗ {r.detector_name}: {r.reason}")

    return "\n".join(lines)
