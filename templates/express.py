"""
Express.js detector templates — HTTP error rate, request latency,
middleware timeout, event loop saturation (complements Node.js templates).
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class ExpressTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── HTTP 5xx rate ─────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Express HTTP 5xx error rate high",
            description="Express.js HTTP 5xx error rate elevated. Warn: >1%  Critical: >5%",
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
            tags=["express", "http", "errors"],
        ))

        # ── Request latency ───────────────────────────────────────────────────
        if baseline and baseline.latency_p99_ms:
            warn_t = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            desc = f"Express request latency anomaly. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms"
            threshold_type = "dynamic"
        else:
            warn_t, anomaly_t = 500, 1000
            desc = "Express request latency high. Warn: >500ms  Critical: >1000ms"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Express request latency high",
            description=desc,
            severity="Major",
            signalflow=f"""
A = data("http.server.duration", filter={f}).percentile(pct=99, over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence="high",
            tags=["express", "http", "latency"],
        ))

        # ── Unhandled promise rejections / uncaught exceptions ────────────────
        # Node.js/Express: these crash the process or trigger error middleware
        detectors.append(DetectorTemplate(
            name=f"[{service}] Express unhandled promise rejections",
            description="Express.js unhandled promise rejections detected — application stability at risk",
            severity="Critical",
            signalflow=f"""
A = data("nodejs.unhandled_rejection.count", filter={f}).sum(over="5m")
detect(when(A > 1), lasting="5m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["express", "nodejs", "exceptions"],
        ))

        # ── Middleware timeout ────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Express middleware timeout rate",
            description="Express middleware or route handler timeout rate elevated — possible blocking I/O on event loop",
            severity="Warning",
            signalflow=f"""
total = data("http.server.request.count", filter={f}).sum(over="5m")
timeouts = data("http.server.request.count", filter={f} and filter("http.status_code", "504")).sum(over="5m")
timeout_pct = timeouts / total * 100
detect(when(timeout_pct > 2), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["express", "http", "timeout"],
        ))

        # ── Active connections ────────────────────────────────────────────────
        # Node.js single-threaded: too many active handles → event loop saturation
        detectors.append(DetectorTemplate(
            name=f"[{service}] Express active HTTP connections high",
            description="Express active HTTP connections high — event loop may be saturated. Warn: >500  Critical: >1000",
            severity="Warning",
            signalflow=f"""
A = data("nodejs.handles.active", filter={f}).mean(over="2m")
detect(when(A > 1000), lasting="2m").publish("Critical")
detect(when(A > 500) and when(A <= 1000), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["express", "nodejs", "concurrency"],
        ))

        return detectors
