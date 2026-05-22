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


def probe_existing_metrics(
    api_base: str,
    token: str,
    service: str,
    environment: str | None,
    candidate_metrics: set[str],
) -> set[str]:
    """
    Query MTS catalog to find which of the candidate_metrics actually have
    data for this service. Returns the subset that exist.

    Uses a single bulk query — one API call regardless of how many metrics.
    """
    if not candidate_metrics:
        return set()

    filters = [f'sf_service:"{service}"']
    if environment:
        filters.append(f'sf_environment:"{environment}"')

    existing: set[str] = set()
    metrics_list = sorted(candidate_metrics)

    for batch_start in range(0, len(metrics_list), 20):
        batch = metrics_list[batch_start:batch_start + 20]
        metric_filter = " OR ".join(f'sf_metric:"{m}"' for m in batch)
        query = f'({metric_filter}) AND {" AND ".join(filters)}'

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
                    existing.add(metric)
        except Exception as e:
            logger.warning("metric_filter: probe failed for %s batch: %s", service, e)
            existing.update(batch)

    logger.debug("metric_filter: %s/%s — %d/%d metrics exist: %s",
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
    query = " AND ".join(filters)

    try:
        qs = urllib.parse.urlencode({"query": query, "limit": 20})
        url = f"{api_base}/v2/metrictimeseries?{qs}"
        req = urllib.request.Request(
            url, headers={"X-SF-Token": token, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
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
