"""
Flask detector templates — request latency, error rate, exception rate.
Applies to Flask and FastAPI services (both use similar OTel instrumentation).
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class FlaskTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── HTTP 5xx rate ─────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Flask HTTP 5xx error rate high",
            description="Flask HTTP 5xx error rate elevated. Warn: >1%  Critical: >5%",
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
            tags=["flask", "http", "errors"],
        ))

        # ── Request latency (p99) ─────────────────────────────────────────────
        if baseline and baseline.latency_p99_ms:
            warn_t = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            desc = f"Flask request latency anomaly. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms"
            threshold_type = "dynamic"
        else:
            warn_t, anomaly_t = 500, 1000
            desc = "Flask request latency high. Warn: >500ms  Critical: >1000ms"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Flask request latency high",
            description=desc,
            severity="Major",
            signalflow=f"""
A = data("http.server.duration", filter={f}).percentile(pct=99, over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence="high",
            tags=["flask", "http", "latency"],
        ))

        # ── Unhandled exception rate ──────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Flask unhandled exception rate",
            description="Flask unhandled exceptions (500 errors from exceptions) — check application logs",
            severity="Major",
            signalflow=f"""
A = data("http.server.request.count", filter={f} and filter("http.status_code", "500")).sum(over="5m")
detect(when(A > 10), lasting="5m").publish("Warning")
detect(when(A > 50), lasting="2m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["flask", "exceptions"],
        ))

        # ── Active request concurrency ────────────────────────────────────────
        # Flask/Gunicorn: too many concurrent requests → WSGI worker saturation
        detectors.append(DetectorTemplate(
            name=f"[{service}] Flask active request concurrency high",
            description="Flask active concurrent requests high — WSGI workers may be saturated. Warn: >50  Critical: >100",
            severity="Warning",
            signalflow=f"""
A = data("http.server.active_requests", filter={f}).mean(over="2m")
detect(when(A > 100), lasting="2m").publish("Critical")
detect(when(A > 50) and when(A <= 100), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["flask", "concurrency"],
        ))

        return detectors
