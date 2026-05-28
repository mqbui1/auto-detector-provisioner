"""
APM detector templates — latency, error rate, request rate.
Applies to all services regardless of tech stack.
"""
from __future__ import annotations
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


class APMTemplates:
    """Best practice detectors for APM signals — applies to all services."""

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Latency ──────────────────────────────────────────────────────────

        if baseline and baseline.latency_mean_ms and baseline.latency_stddev_ms and baseline.is_reliable():
            warn_thresh = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_thresh = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            threshold_type = "dynamic"
            confidence = "high"
        else:
            # Fall back to fixed best-practice thresholds
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
            severity="Major",
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
                + (f"Thresholds set at mean+2σ (warn) / mean+3σ (critical) from {baseline.sample_count} "
                   f"sampled requests over the baseline window — statistically significant deviation. "
                   f"Tune by adjusting the σ multiplier if you see too many false positives."
                   if threshold_type == "dynamic" else
                   "Fixed thresholds (1s warn / 3s critical) from Splunk APM best practices. "
                   "Tune once baseline data is available (re-run with --baseline-window-hours 24). "
                   "Source: Google SRE Book §6 (SLIs); Splunk APM Detector Best Practices; "
                   "OTel Semantic Conventions v1.24 (service.request.duration).")
            ),
        ))

        # ── Error rate ────────────────────────────────────────────────────────

        if baseline and baseline.error_rate_pct is not None and baseline.is_reliable():
            # Dynamic: baseline error rate + buffer
            warn_thresh_err = round(max(baseline.error_rate_pct * 2, 1.0), 2)
            anomaly_thresh_err = round(max(baseline.error_rate_pct * 4, 5.0), 2)
            err_threshold_type = "dynamic"
            err_confidence = "high"
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
            severity="Major",
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
