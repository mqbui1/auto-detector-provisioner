"""
Metric existence filter — checks which metrics actually have data for a
service/environment combination, then filters out detectors whose required
metrics don't exist. This prevents ghost detectors for metrics a service
never emits (e.g. JVM heap metrics on a Go service, gRPC client metrics on
a server-only service, HTTP 429 metrics on an internal service with no
rate-limiting).
"""
from __future__ import annotations

import logging
import re
import urllib.error
import urllib.parse
import urllib.request
import json

logger = logging.getLogger(__name__)

# Regex to extract metric names from SignalFlow data() calls
_METRIC_RE = re.compile(r'data\(\s*"([^"]+)"')

def extract_metrics_from_signalflow(signalflow: str) -> set[str]:
    """Extract all metric names from data() calls in a SignalFlow program."""
    return set(_METRIC_RE.findall(signalflow))


def _query_mts_batch(
    api_base: str,
    token: str,
    batch: list[str],
    filters: list[str],
) -> set[str]:
    """Run one MTS catalog batch query, return metric names found."""
    metric_filter = " OR ".join(f'sf_metric:"{m}"' for m in batch)
    query = f'({metric_filter}) AND {" AND ".join(filters)}'
    found: set[str] = set()
    try:
        qs = urllib.parse.urlencode({"query": query, "limit": len(batch) * 2})
        url = f"{api_base}/v2/metrictimeseries?{qs}"
        req = urllib.request.Request(
            url, headers={"X-SF-Token": token, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        for mts in (data.get("results") or []):
            metric = mts.get("metric") or mts.get("name") or ""
            if metric:
                found.add(metric)
    except Exception as e:
        logger.warning("metric_filter: probe failed (filters=%s): %s", filters, e)
        found.update(batch)  # fail open
    return found


def probe_existing_metrics(
    api_base: str,
    token: str,
    service: str,
    environment: str | None,
    candidate_metrics: set[str],
) -> set[str]:
    """
    Check which candidate_metrics have had data in the last hour for this
    service. Uses SignalFlow to verify recent data exists — stricter than
    MTS catalog which may return metrics that existed historically but have
    no current data.
    """
    if not candidate_metrics:
        return set()

    import time
    import urllib.parse as _up

    env_f = f'filter("sf_environment", "{environment}") and ' if environment else ""
    svc_f = f'filter("sf_service", "{service}")'
    combined = f"{env_f}{svc_f}"

    now_ms = int(time.time() * 1000)
    start_ms = now_ms - 3600 * 1000  # last 1 hour

    existing: set[str] = set()

    # Batch into groups of 10 — each group is one SignalFlow job
    metrics_list = sorted(candidate_metrics)
    for batch_start in range(0, len(metrics_list), 10):
        batch = metrics_list[batch_start:batch_start + 10]
        # Publish each metric; check which ones return values
        lines = [f'data("{m}", filter={combined}).sum(over="1h").publish("{i}")'
                 for i, m in enumerate(batch)]
        program = "\n".join(lines)

        qs = _up.urlencode({"start": start_ms, "stop": now_ms,
                            "resolution": 3600000, "immediate": "true"})
        url = f"{api_base}/v2/signalflow/execute?{qs}"
        req = urllib.request.Request(
            url, data=program.encode("utf-8"),
            headers={"X-SF-Token": token, "Content-Type": "text/plain"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data_lines: list[str] = []
                current_event: str | None = None
                seen_labels: set[str] = set()
                for raw in resp:
                    line = raw.rstrip(b"\r\n")
                    if line.startswith(b"event:"):
                        current_event = line[6:].strip().decode()
                    elif line.startswith(b"data:"):
                        data_lines.append(line[5:].strip().decode())
                    elif line == b"":
                        if data_lines and current_event == "data":
                            try:
                                msg = json.loads("\n".join(data_lines))
                                for ts in (msg.get("data") or []):
                                    v = ts.get("value")
                                    label = str(ts.get("key", {}).get("label", ""))
                                    if v is not None and float(v) > 0 and label:
                                        seen_labels.add(label)
                            except Exception:
                                pass
                        data_lines = []
                        current_event = None
                for i, m in enumerate(batch):
                    if str(i) in seen_labels:
                        existing.add(m)
        except Exception as e:
            logger.warning("metric_filter: probe failed for %s batch: %s", service, e)
            # Fail open — keep all metrics in this batch
            existing.update(batch)

    logger.debug("metric_filter: %s/%s — %d/%d metrics have recent data: %s",
                 environment, service, len(existing), len(candidate_metrics),
                 sorted(existing)[:10])
    return existing


def probe_http_status_codes_exist(
    api_base: str,
    token: str,
    service: str,
    environment: str | None,
) -> bool:
    """
    Check whether service.request.count has an http.status_code dimension
    for this service — i.e. whether the service actually emits HTTP status
    codes. gRPC-only services emit service.request.count but without
    http.status_code, so HTTP pattern detectors should be dropped for them.

    Strategy: query MTS for service.request.count and inspect the dimensions
    of the returned MTS entries for the presence of http.status_code.
    """
    filters = [f'sf_service:"{service}"', 'sf_metric:"service.request.count"']
    if environment:
        filters.append(f'sf_environment:"{environment}"')
    # service.request.count is always APM-promoted to sf_service, so no
    # fallback to service.name needed here.
    query = " AND ".join(filters)

    try:
        qs = urllib.parse.urlencode({"query": query, "limit": 20})
        url = f"{api_base}/v2/metrictimeseries?{qs}"
        req = urllib.request.Request(
            url, headers={"X-SF-Token": token, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            chunks = []
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            data = json.loads(b"".join(chunks).decode("utf-8"))
        for mts in (data.get("results") or []):
            dims = mts.get("dimensions") or {}
            if "http.status_code" in dims or "http.response.status_code" in dims:
                return True
        return False
    except Exception as e:
        logger.warning("metric_filter: http status code probe failed for %s: %s", service, e)
        return True  # fail open — keep HTTP detectors on error


def filter_detectors_by_metric_existence(
    detectors: list,
    existing_metrics: set[str],
) -> list:
    """
    Remove detectors whose required metrics don't exist for this service.

    A detector is kept if:
    - It has no data() calls at all (threshold-only logic), OR
    - At least one of its required metrics exists for this service
    """
    kept = []
    dropped = []
    for det in detectors:
        required = extract_metrics_from_signalflow(det.signalflow)
        if not required:
            # No non-universal metrics — always keep (APM span-based)
            kept.append(det)
        elif required & existing_metrics:
            # At least one required metric exists
            kept.append(det)
        else:
            dropped.append(det.name)

    if dropped:
        logger.debug("metric_filter: dropped %d detectors (no metric data): %s",
                     len(dropped), dropped[:5])
    return kept
