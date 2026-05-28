"""
FastAPI detector templates — request latency, 5xx rate, async task failures,
background task errors, dependency injection failures.
FastAPI uses the same OTel HTTP semantic conventions as Flask but adds
async-specific patterns.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class FastAPITemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── HTTP 5xx rate ─────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] FastAPI HTTP 5xx error rate high",
            description="FastAPI HTTP 5xx error rate elevated. Warn: >1%  Critical: >5%",
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
            tags=["fastapi", "http", "errors"],
        ))

        # ── Request latency (p99) ─────────────────────────────────────────────
        if baseline and baseline.latency_p99_ms:
            warn_t = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            desc = f"FastAPI request latency anomaly. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms"
            threshold_type = "dynamic"
        else:
            warn_t, anomaly_t = 300, 800
            desc = "FastAPI request latency high (async baseline). Warn: >300ms  Critical: >800ms"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] FastAPI request latency high",
            description=desc,
            severity="Major",
            signalflow=f"""
A = data("http.server.duration", filter={f}).percentile(pct=99, over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence="high",
            tags=["fastapi", "http", "latency"],
        ))

        # ── 422 Validation error rate ─────────────────────────────────────────
        # FastAPI-specific: Pydantic validation errors (422 Unprocessable Entity)
        # indicate schema mismatch — often a breaking API change
        detectors.append(DetectorTemplate(
            name=f"[{service}] FastAPI validation error rate (422) spike",
            description="FastAPI Pydantic validation errors (422) elevated — possible API contract mismatch or bad client payload",
            severity="Warning",
            signalflow=f"""
total = data("http.server.request.count", filter={f}).sum(over="5m")
val_errors = data("http.server.request.count", filter={f} and filter("http.status_code", "422")).sum(over="5m")
error_pct = val_errors / total * 100
detect(when(error_pct > 5), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["fastapi", "validation", "errors"],
        ))

        # ── Background task failures ──────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] FastAPI background task failures",
            description="FastAPI BackgroundTask exceptions detected — fire-and-forget tasks failing silently",
            severity="Warning",
            signalflow=f"""
A = data("fastapi.background_task.exceptions", filter={f}).sum(over="5m")
detect(when(A > 5), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="low",
            tags=["fastapi", "background_tasks"],
        ))

        return detectors
