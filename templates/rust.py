"""
Rust / Actix-web detector templates — request latency, error rate,
worker thread saturation. Rust services typically don't emit rich
runtime metrics, so this focuses on HTTP and gRPC signals via OTel spans.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class RustTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── HTTP 5xx error rate ───────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Rust service HTTP 5xx error rate high",
            description="Rust HTTP service 5xx error rate elevated. Warn: >1%  Critical: >5%",
            severity="Major",
            signalflow=f"""
total = data("http.server.request.count", filter={f}).sum(over="2m")
errors = data("http.server.request.count", filter={f} and filter("http.status_code", "5*")).sum(over="2m")
error_pct = errors / total * 100
detect(when(error_pct > 5), lasting="2m").publish("Critical")
detect(when(error_pct > 1) and when(error_pct <= 5), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["rust", "http", "errors"],
        ))

        # ── Request latency ───────────────────────────────────────────────────
        if baseline and baseline.latency_p99_ms:
            warn_t = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            desc = f"Rust service request latency anomaly. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms"
            threshold_type = "dynamic"
        else:
            warn_t, anomaly_t = 200, 500
            desc = "Rust service request latency high. Warn: >200ms  Critical: >500ms"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Rust service request latency high",
            description=desc,
            severity="Major",
            signalflow=f"""
A = data("http.server.duration", filter={f}).percentile(pct=99, over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence="high",
            tags=["rust", "http", "latency"],
        ))

        # ── Panic rate ────────────────────────────────────────────────────────
        # Rust panics manifest as 500s with specific error tags
        detectors.append(DetectorTemplate(
            name=f"[{service}] Rust service panic / internal error rate",
            description="Rust service 500 Internal Server Error rate elevated — possible panic or unhandled error. Warn: >0.5%  Critical: >2%",
            severity="Major",
            signalflow=f"""
total = data("http.server.request.count", filter={f}).sum(over="5m")
panics = data("http.server.request.count", filter={f} and filter("http.status_code", "500")).sum(over="5m")
pct = panics / total * 100
detect(when(pct > 2), lasting="5m").publish("Critical")
detect(when(pct > 0.5) and when(pct <= 2), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["rust", "errors", "panic"],
        ))

        return detectors
