"""
Baseline learner — observes a service over a time window and computes
dynamic thresholds for detector generation.
"""
from __future__ import annotations

import json
import logging
import math
import time
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urlencode
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class MetricBaseline:
    metric: str
    mean: float
    stddev: float
    p50: float
    p95: float
    p99: float
    sample_count: int
    unit: str = ""

    def warn_threshold(self, z: float = 2.0) -> float:
        return self.mean + z * self.stddev

    def anomaly_threshold(self, z: float = 3.0) -> float:
        return self.mean + z * self.stddev

    def is_reliable(self, min_samples: int = 30) -> bool:
        return self.sample_count >= min_samples and self.stddev > 0


@dataclass
class ServiceBaseline:
    service: str
    environment: str
    learned_at: float = field(default_factory=time.time)
    window_hours: int = 24
    metrics: dict[str, MetricBaseline] = field(default_factory=dict)
    # APM baselines
    latency_mean_ms: float | None = None
    latency_p99_ms: float | None = None
    latency_stddev_ms: float | None = None
    error_rate_pct: float | None = None
    request_rate_per_min: float | None = None
    sample_count: int = 0

    def is_reliable(self, min_samples: int = 30) -> bool:
        return self.sample_count >= min_samples


def _api_get(api_base: str, token: str, path: str, params: dict | None = None) -> dict:
    qs = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None})
    url = f"{api_base}{path}" + (f"?{qs}" if qs else "")
    req = urllib.request.Request(url, headers={"X-SF-Token": token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:300].decode()}")


def _execute_signalflow(api_base: str, token: str, program: str, start_ms: int, end_ms: int, resolution_ms: int = 60000) -> list[float]:
    """Execute a SignalFlow program and return the data points."""
    qs = urllib.parse.urlencode({
        "start": start_ms,
        "stop": end_ms,
        "resolution": resolution_ms,
        "immediate": "true",
    })
    url = f"{api_base}/v2/signalflow/execute?{qs}"
    body = program.encode("utf-8")
    req = urllib.request.Request(
        url, data=body,
        headers={"X-SF-Token": token, "Content-Type": "text/plain"},
        method="POST",
    )
    values = []
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            for line in resp:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except Exception:
                    continue
                if msg.get("type") == "data":
                    for ts_data in (msg.get("data") or []):
                        v = ts_data.get("value")
                        if v is not None:
                            values.append(float(v))
    except Exception as e:
        logger.warning("SignalFlow execution failed: %s", e)
    return values


def _compute_stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"mean": 0, "stddev": 0, "p50": 0, "p95": 0, "p99": 0, "count": 0}
    n = len(values)
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / n
    stddev = math.sqrt(variance)
    sorted_vals = sorted(values)
    p50 = sorted_vals[int(n * 0.50)]
    p95 = sorted_vals[min(int(n * 0.95), n - 1)]
    p99 = sorted_vals[min(int(n * 0.99), n - 1)]
    return {"mean": mean, "stddev": stddev, "p50": p50, "p95": p95, "p99": p99, "count": n}


def _learn_apm_baseline(api_base: str, token: str, service: str, environment: str, window_hours: int) -> dict:
    """Learn APM latency and error rate baseline via SignalFlow."""
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - window_hours * 3600 * 1000
    env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""

    svc_filter = f'filter("sf_service", "{service}")'
    base_filter = f"{env_filter}{svc_filter}"

    # Latency — try OTel semantic convention first, fall back to Splunk APM metric names
    latency_values: list[float] = []
    for latency_metric in [
        "service.request.duration",                   # OTel semantic convention (ms)
        "service.request.duration.ns.median",         # Splunk APM (nanoseconds)
        "spans.duration.ns.median",                   # Splunk APM spans metric
    ]:
        prog = f'data("{latency_metric}", {base_filter}).mean().publish()'
        vals = _execute_signalflow(api_base, token, prog, start_ms, now_ms)
        if vals and any(v > 0 for v in vals):
            # Convert nanoseconds to milliseconds if metric name indicates ns
            if ".ns." in latency_metric:
                vals = [v / 1_000_000 for v in vals]
            latency_values = vals
            logger.debug("Baseline: using latency metric %s (%d samples)", latency_metric, len(vals))
            break

    # Error rate — try OTel count with error filter, fall back to Splunk APM error metric
    error_values: list[float] = []
    for err_prog in [
        (f'A = data("service.request.count", {base_filter}, filter("error", "true")).sum()\n'
         f'B = data("service.request.count", {base_filter}).sum()\n'
         f'(A/B * 100).publish()'),
        (f'A = data("spans.count", {base_filter}, filter("sf_error", "true")).sum()\n'
         f'B = data("spans.count", {base_filter}).sum()\n'
         f'(A/B * 100).publish()'),
    ]:
        vals = _execute_signalflow(api_base, token, err_prog, start_ms, now_ms)
        if vals:
            error_values = vals
            break

    latency_stats = _compute_stats(latency_values)
    error_stats = _compute_stats(error_values)

    return {
        "latency": latency_stats,
        "error_rate": error_stats,
    }


def _learn_metric_baseline(api_base: str, token: str, metric: str, service: str, environment: str, window_hours: int) -> list[float]:
    """Learn baseline for a specific metric via SignalFlow."""
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - window_hours * 3600 * 1000
    env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
    svc_filter = f'filter("sf_service", "{service}") and ' if service else ""

    program = f'data("{metric}", {env_filter}{svc_filter}True).mean().publish()'
    return _execute_signalflow(api_base, token, program, start_ms, now_ms)


def learn_baseline(
    realm: str,
    token: str,
    service: str,
    environment: str,
    window_hours: int = 24,
    metrics_to_learn: list[str] | None = None,
    output_dir: Path | None = None,
) -> ServiceBaseline:
    """
    Learn baseline for a service by observing metrics and APM data
    over the given window. Returns a ServiceBaseline with computed thresholds.
    """
    api_base = f"https://api.{realm}.signalfx.com"
    logger.info("Baseline: learning %s/%s (window=%dh)", environment, service, window_hours)

    baseline = ServiceBaseline(
        service=service,
        environment=environment,
        window_hours=window_hours,
    )

    # Learn APM baseline
    try:
        apm = _learn_apm_baseline(api_base, token, service, environment, window_hours)
        lat = apm["latency"]
        err = apm["error_rate"]
        if lat["count"] > 0:
            baseline.latency_mean_ms = lat["mean"]
            baseline.latency_p99_ms = lat["p99"]
            baseline.latency_stddev_ms = lat["stddev"]
            baseline.sample_count = int(lat["count"])
        if err["count"] > 0:
            baseline.error_rate_pct = err["mean"]
        logger.info("Baseline: APM latency=%.1fms p99=%.1fms error_rate=%.2f%%",
                    baseline.latency_mean_ms or 0,
                    baseline.latency_p99_ms or 0,
                    baseline.error_rate_pct or 0)
    except Exception as e:
        logger.warning("Baseline: APM learning failed: %s", e)

    # Learn specific metrics if provided
    for metric in (metrics_to_learn or []):
        try:
            values = _learn_metric_baseline(api_base, token, metric, service, environment, window_hours)
            if values:
                stats = _compute_stats(values)
                baseline.metrics[metric] = MetricBaseline(
                    metric=metric,
                    mean=stats["mean"],
                    stddev=stats["stddev"],
                    p50=stats["p50"],
                    p95=stats["p95"],
                    p99=stats["p99"],
                    sample_count=int(stats["count"]),
                )
                logger.info("Baseline: %s mean=%.2f stddev=%.2f", metric, stats["mean"], stats["stddev"])
        except Exception as e:
            logger.warning("Baseline: metric %s learning failed: %s", metric, e)

    # Persist to disk if output_dir provided
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / f"{environment}__{service}.json"
        _save_baseline(baseline, path)
        logger.info("Baseline: saved to %s", path)

    return baseline


def _save_baseline(baseline: ServiceBaseline, path: Path) -> None:
    data = {
        "service": baseline.service,
        "environment": baseline.environment,
        "learned_at": baseline.learned_at,
        "window_hours": baseline.window_hours,
        "sample_count": baseline.sample_count,
        "latency_mean_ms": baseline.latency_mean_ms,
        "latency_p99_ms": baseline.latency_p99_ms,
        "latency_stddev_ms": baseline.latency_stddev_ms,
        "error_rate_pct": baseline.error_rate_pct,
        "request_rate_per_min": baseline.request_rate_per_min,
        "metrics": {
            k: {
                "mean": v.mean, "stddev": v.stddev,
                "p50": v.p50, "p95": v.p95, "p99": v.p99,
                "sample_count": v.sample_count, "unit": v.unit,
            }
            for k, v in baseline.metrics.items()
        },
    }
    path.write_text(json.dumps(data, indent=2))


def load_baseline(path: Path) -> ServiceBaseline | None:
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    baseline = ServiceBaseline(
        service=data["service"],
        environment=data["environment"],
        learned_at=data.get("learned_at", 0),
        window_hours=data.get("window_hours", 24),
        sample_count=data.get("sample_count", 0),
        latency_mean_ms=data.get("latency_mean_ms"),
        latency_p99_ms=data.get("latency_p99_ms"),
        latency_stddev_ms=data.get("latency_stddev_ms"),
        error_rate_pct=data.get("error_rate_pct"),
        request_rate_per_min=data.get("request_rate_per_min"),
    )
    for metric, stats in (data.get("metrics") or {}).items():
        baseline.metrics[metric] = MetricBaseline(
            metric=metric,
            mean=stats["mean"], stddev=stats["stddev"],
            p50=stats["p50"], p95=stats["p95"], p99=stats["p99"],
            sample_count=stats["sample_count"], unit=stats.get("unit", ""),
        )
    return baseline
