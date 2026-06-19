"""
APM detector templates — latency, error rate, request rate.
Applies to all services regardless of tech stack.
"""
from __future__ import annotations
import math
from dataclasses import dataclass, field
from typing import Any


@dataclass
class DetectorTemplate:
    name: str
    description: str
    severity: str          # Critical, Major, Minor, Warning, Info
    signalflow: str
    threshold_type: str    # dynamic, fixed, hybrid
    confidence: str        # high, medium, low
    tags: list[str] = field(default_factory=list)
    # Metric names this detector requires. If none of these exist for the service,
    # the detector is skipped. Empty = always create (e.g. APM span-based detectors).
    required_metrics: list[str] = field(default_factory=list)
    # Human-readable rationale: why this detector exists + where thresholds come from
    rationale: str = ""
    # Estimated alert frequency: how many times/day this detector would fire on average traffic.
    # Computed analytically from baseline stats — None means unknown (fixed thresholds).
    simulated_alerts_per_day: float | None = None


def _breach_rate(mean: float, stddev: float, threshold: float) -> float:
    """Estimate fraction of time-windows exceeding threshold (Gaussian approximation)."""
    if stddev <= 0:
        return 0.0 if mean <= threshold else 1.0
    z = (threshold - mean) / stddev
    return 0.5 * math.erfc(z / math.sqrt(2))


def _alerts_per_day(breach_rate: float, window_minutes: int = 5) -> float:
    """Convert a breach rate fraction to expected alert firings per day."""
    windows_per_day = 24 * 60 / window_minutes
    return round(breach_rate * windows_per_day, 1)


class APMTemplates:
    """Best practice detectors for APM signals — applies to all services."""

    @staticmethod
    def templates(
        service: str,
        environment: str,
        baseline: Any | None = None,
        is_critical_path: bool = False,
    ) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        # Critical-path services get tighter severity labelling
        base_severity = "Critical" if is_critical_path else "Major"

        detectors = []

        # ── Latency ──────────────────────────────────────────────────────────
        # Prefer percentile-based thresholds (p99 warn, 1.5×p99 critical) —
        # more accurate for log-normal latency than mean+Nσ.
        # Fall back to confidence-scaled σ bands when percentiles unavailable.

        latency_simulated: float | None = None

        if baseline and baseline.latency_p99_ms and baseline.is_reliable():
            warn_thresh = round(baseline.latency_p99_ms, 1)
            anomaly_thresh = round(baseline.latency_p99_ms * 1.5, 1)
            threshold_type = "dynamic"
            confidence = "high"
            # p99 by definition: 1% of windows exceed it → ~2.9 alerts/day
            latency_simulated = _alerts_per_day(0.01)
        elif baseline and baseline.latency_mean_ms and baseline.latency_stddev_ms and baseline.is_reliable():
            w_sigma, c_sigma = baseline.sigma_multipliers()
            warn_thresh = round(baseline.latency_mean_ms + w_sigma * baseline.latency_stddev_ms, 1)
            anomaly_thresh = round(baseline.latency_mean_ms + c_sigma * baseline.latency_stddev_ms, 1)
            threshold_type = "dynamic"
            confidence = "high"
            br = _breach_rate(baseline.latency_mean_ms, baseline.latency_stddev_ms, warn_thresh)
            latency_simulated = _alerts_per_day(br)
        else:
            warn_thresh = 1000    # 1s
            anomaly_thresh = 3000  # 3s
            threshold_type = "fixed"
            confidence = "medium"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Latency anomaly (p99)",
            description=(
                f"Service {service} p99 latency exceeds baseline. "
                f"Warn: >{warn_thresh}ms  Anomaly: >{anomaly_thresh}ms"
            ),
            severity=base_severity,
            simulated_alerts_per_day=latency_simulated,
            signalflow=f"""
A = data("service.request.duration.ns.median", filter={f}).scale(0.000001).mean(over="5m")
A.publish("A")
detect(when(A > {anomaly_thresh}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_thresh}) and when(A <= {anomaly_thresh}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence=confidence,
            required_metrics=["service.request.duration", "service.request.duration.ns.median"],
            tags=["apm", "latency"],
            rationale=(
                "p99 latency is the standard SLI for user-facing latency per Google SRE Book §6. "
                "p99 catches tail latency that p50/p95 miss — the worst 1% of requests often indicates "
                "resource contention, GC pauses, or downstream timeouts. "
                + (f"Thresholds set at p99={warn_thresh}ms (warn) / 1.5×p99={anomaly_thresh}ms (critical) "
                   f"from {baseline.sample_count} samples — percentile-based, no distribution assumptions. "
                   f"Expected ~{latency_simulated} alerts/day on normal traffic. "
                   f"Tune by widening the multiplier (e.g. 2×p99) if you see too many false positives."
                   if threshold_type == "dynamic" else
                   "Fixed thresholds (1s warn / 3s critical) from Splunk APM best practices. "
                   "Tune once baseline data is available (re-run with --baseline-window-hours 24). "
                   "Source: Google SRE Book §6 (SLIs); Splunk APM Detector Best Practices; "
                   "OTel Semantic Conventions v1.24 (service.request.duration).")
            ),
        ))

        # ── Error rate ────────────────────────────────────────────────────────

        err_simulated: float | None = None

        if baseline and baseline.error_rate_pct is not None and baseline.is_reliable():
            w_sigma, c_sigma = baseline.sigma_multipliers()
            warn_thresh_err = round(max(baseline.error_rate_pct * 2, 1.0), 2)
            anomaly_thresh_err = round(max(baseline.error_rate_pct * 4, 5.0), 2)
            err_threshold_type = "dynamic"
            err_confidence = "high"
            if baseline.error_rate_stddev_pct:
                br = _breach_rate(baseline.error_rate_pct, baseline.error_rate_stddev_pct, warn_thresh_err)
                err_simulated = _alerts_per_day(br)
        else:
            warn_thresh_err = 1.0   # 1%
            anomaly_thresh_err = 5.0  # 5%
            err_threshold_type = "fixed"
            err_confidence = "medium"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Error rate anomaly",
            description=(
                f"Service {service} error rate exceeds threshold. "
                f"Warn: >{warn_thresh_err}%  Anomaly: >{anomaly_thresh_err}%"
            ),
            severity=base_severity,
            simulated_alerts_per_day=err_simulated,
            signalflow=f"""
A = data("service.request.count", filter={f} and filter("sf_error", "true")).sum(over="5m").fill(0)
B = data("service.request.count", filter={f}).sum(over="5m")
A.publish("A")
B.publish("B")
error_rate = (A / B * 100)
error_rate.publish("error_rate_pct")
detect(when(error_rate > {anomaly_thresh_err}), lasting="5m").publish("Anomaly")
detect(when(error_rate > {warn_thresh_err}) and when(error_rate <= {anomaly_thresh_err}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=err_threshold_type,
            confidence=err_confidence,
            tags=["apm", "error_rate"],
            rationale=(
                "Error rate is a core SLI per Google SRE Book §6 and the four golden signals "
                "(latency, traffic, errors, saturation). Splunk APM marks spans with sf_error=true "
                "for any HTTP 5xx or exception. "
                + (f"Thresholds set at 2× (warn) / 4× (critical) the observed baseline error rate "
                   f"of {baseline.error_rate_pct:.2f}%, giving headroom for normal variance. "
                   f"Tune the multipliers if your service has bursty but acceptable errors."
                   if err_threshold_type == "dynamic" else
                   "Fixed thresholds (1% warn / 5% critical) from Splunk APM best practices and "
                   "the SRE workbook availability targets. Tune once you know your error budget. "
                   "Source: Google SRE Book §6 (error budgets); Splunk APM best practices; "
                   "OTel Semantic Conventions v1.24 (service.request.count + error attribute).")
            ),
        ))

        # ── Error budget burn-rate ────────────────────────────────────────────
        # SRE Book multiwindow burn-rate: fire when error rate would exhaust the
        # monthly error budget within 1 hour (14.4× budget) or 6 hours (2.4× budget).
        # Defaults to 99.9% SLO (0.1% monthly budget). This is the most actionable
        # SLO-aligned alert — absolute rate alerts miss slow burns.
        _budget_pct = 0.1  # 99.9% SLO → 0.1% monthly error budget
        _burn_1h = round(_budget_pct * 14.4, 2)   # exhausted in 1h
        _burn_6h = round(_budget_pct * 6.0, 2)    # exhausted in 6h
        detectors.append(DetectorTemplate(
            name=f"[{service}] Error budget burn rate critical",
            description=(
                f"Error rate indicates the monthly error budget (99.9% SLO) would be exhausted "
                f"within 1 hour (>{_burn_1h}%) or within 6 hours (>{_burn_6h}%). "
                f"Immediate action required."
            ),
            severity="Critical",
            signalflow=f"""
A = data("service.request.count", filter={f} and filter("sf_error", "true")).sum(over="1m").fill(0)
B = data("service.request.count", filter={f}).sum(over="1m")
error_rate_1m = (A / B * 100)
A6 = data("service.request.count", filter={f} and filter("sf_error", "true")).sum(over="6m").fill(0)
B6 = data("service.request.count", filter={f}).sum(over="6m")
error_rate_6m = (A6 / B6 * 100)
error_rate_1m.publish("error_rate_1m")
error_rate_6m.publish("error_rate_6m")
detect(when(error_rate_1m > {_burn_1h}), lasting="1m").publish("BurnRate1h")
detect(when(error_rate_6m > {_burn_6h}) and when(error_rate_1m <= {_burn_1h}), lasting="5m").publish("BurnRate6h")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["apm", "error_rate", "slo"],
            rationale=(
                f"Multiwindow burn-rate alert from Google SRE Workbook Chapter 5. "
                f"A 1-minute error rate >{_burn_1h}% would exhaust the 99.9% SLO budget in <1 hour "
                f"(14.4× consumption rate). A 6-minute rate >{_burn_6h}% exhausts it in <6 hours. "
                f"This catches slow burns that absolute-rate alerts miss. "
                f"Tune _budget_pct if your SLO is different (e.g. 99% SLO → budget=1%, 1h burn=14.4%). "
                f"Source: Google SRE Workbook Chapter 5 (Alerting on SLOs)."
            ),
        ))

        # ── Request rate drop ─────────────────────────────────────────────────

        if baseline and baseline.request_rate_per_min and baseline.is_reliable():
            drop_thresh = round(baseline.request_rate_per_min * 0.5, 1)
            detectors.append(DetectorTemplate(
                name=f"[{service}] Request rate drop",
                description=f"Service {service} request rate dropped >50% from baseline ({baseline.request_rate_per_min:.1f}/min)",
                severity="Major",
                signalflow=f"""
A = data("service.request.count", filter={f}).sum(over="5m")
A.publish("A")
detect(when(A < {drop_thresh}), lasting="10m").publish("Warning")
""".strip(),
                threshold_type="dynamic",
                confidence="high",
                tags=["apm", "availability"],
            ))

        # ── No data / silent service ──────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Service stopped emitting spans",
            description=f"Service {service} has stopped emitting trace data — possible silent failure or deployment issue.",
            severity="Critical",
            signalflow=f"""
A = data("service.request.count", filter={f}).sum(over="10m")
A.publish("A")
detect(when(A is None), lasting="10m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["apm", "availability"],
            rationale=(
                "Detects complete absence of trace data — the most critical signal before any "
                "other alert can fire. A service emitting zero spans means either it crashed, "
                "was undeployed, or the OTel collector pipeline broke. "
                "Source: Splunk APM no-data alerting pattern; Google SRE Book §6 (alerting on "
                "absence); OTel Collector health check best practices. The 10-minute window avoids "
                "false positives during rolling restarts — tune if your deploys take longer."
            ),
        ))

        return detectors
