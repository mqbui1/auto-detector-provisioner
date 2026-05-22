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
A = data("service.request.duration", {f}, rollup="p99").mean(over="5m")
detect(when(A > {anomaly_thresh}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_thresh}) and when(A <= {anomaly_thresh}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence=confidence,
            tags=["apm", "latency"],
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
A = data("service.request.count", {f}, filter("error", "true")).sum(over="5m")
B = data("service.request.count", {f}).sum(over="5m")
error_rate = (A / B * 100)
detect(when(error_rate > {anomaly_thresh_err}), lasting="5m").publish("Anomaly")
detect(when(error_rate > {warn_thresh_err}) and when(error_rate <= {anomaly_thresh_err}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=err_threshold_type,
            confidence=err_confidence,
            tags=["apm", "error_rate"],
        ))

        # ── Request rate drop ─────────────────────────────────────────────────

        if baseline and baseline.request_rate_per_min and baseline.is_reliable():
            drop_thresh = round(baseline.request_rate_per_min * 0.5, 1)
            detectors.append(DetectorTemplate(
                name=f"[{service}] Request rate drop",
                description=f"Service {service} request rate dropped >50% from baseline ({baseline.request_rate_per_min:.1f}/min)",
                severity="Major",
                signalflow=f"""
A = data("service.request.count", {f}).sum(over="5m")
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
A = data("service.request.count", {f}).sum(over="10m")
detect(when(A is None), lasting="10m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["apm", "availability"],
        ))

        return detectors
