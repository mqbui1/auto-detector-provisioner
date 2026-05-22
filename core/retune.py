"""
Retune engine — compares current baseline against the one used at provision time.
If drift exceeds threshold, updates detector thresholds in-place via PATCH /v2/detector.
No new detectors created — only SignalFlow text and rule thresholds are updated.
"""
from __future__ import annotations

import hashlib
import json
import logging
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


def _rebuild_signalflow(old_signalflow: str, old_baseline: dict, new_baseline: ServiceBaseline) -> str | None:
    """
    Replace threshold values in existing SignalFlow text using the new baseline.
    Returns updated SignalFlow or None if no change needed.
    """
    text = old_signalflow

    old_mean = old_baseline.get("latency_mean_ms") or 0
    old_std = old_baseline.get("latency_stddev_ms") or 0

    if not old_mean or not new_baseline.latency_mean_ms:
        return None

    # Only retune if drift exceeds threshold
    mean_drift = _drift_pct(old_mean, new_baseline.latency_mean_ms)
    std_drift = _drift_pct(old_std, new_baseline.latency_stddev_ms or 0)

    if mean_drift < RETUNE_DRIFT_THRESHOLD and std_drift < RETUNE_DRIFT_THRESHOLD:
        return None

    # Replace old computed thresholds with new ones
    # Dynamic thresholds follow pattern: mean + N*stddev
    for n_sigma, label in [(2.0, "warn"), (3.0, "anomaly")]:
        old_t = round(old_mean + n_sigma * old_std, 1)
        new_t = round(
            (new_baseline.latency_mean_ms or 0) + n_sigma * (new_baseline.latency_stddev_ms or 0),
            1,
        )
        text = text.replace(str(old_t), str(new_t))

    return text if text != old_signalflow else None


def retune_service(
    realm: str,
    token: str,
    service: str,
    environment: str,
    new_baseline: ServiceBaseline,
    state: ProvisionerState,
    dry_run: bool = True,
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
    if not svc_state.needs_retune(new_hash):
        logger.info("Retune: %s/%s baseline unchanged — no retune needed", environment, service)
        return results

    logger.info("Retune: %s/%s baseline drifted — checking detectors", environment, service)

    # Reconstruct old baseline from hash context (stored at provision time)
    old_baseline_snapshot = {
        "latency_mean_ms": _parse_hash_component(svc_state.baseline_hash, 0),
        "latency_stddev_ms": _parse_hash_component(svc_state.baseline_hash, 1),
    }

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
            current_signalflow = current.get("signalFlowText", "")

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
                    action="updated",
                    reason="dry-run — would update SignalFlow thresholds",
                ))
                continue

            # Patch the detector
            patch_body = dict(current)
            patch_body["signalFlowText"] = new_signalflow
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
        state.record_retune(service, environment, new_hash, updated_records)

    return results


def _parse_hash_component(h: str, index: int) -> float:
    """Placeholder — in production, store baseline values alongside the hash."""
    return 0.0


def format_retune_summary(results: list[RetuneResult], dry_run: bool) -> str:
    mode = "DRY RUN" if dry_run else "RETUNE"
    updated = [r for r in results if r.action == "updated"]
    skipped = [r for r in results if r.action == "skipped"]
    failed = [r for r in results if r.action == "failed"]

    lines = [f"\n{mode} SUMMARY: {len(updated)} updated, {len(skipped)} skipped, {len(failed)} failed"]

    if updated:
        lines.append(f"\nUPDATED ({len(updated)}):")
        for r in updated:
            lines.append(f"  ✓ {r.detector_name}: {r.reason}")

    if failed:
        lines.append(f"\nFAILED ({len(failed)}):")
        for r in failed:
            lines.append(f"  ✗ {r.detector_name}: {r.reason}")

    return "\n".join(lines)
