"""
Django detector templates — request latency, 5xx rate, ORM slow queries,
cache hit rate, Celery task failures (when used with Django).
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class DjangoTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── HTTP 5xx rate ─────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Django HTTP 5xx error rate high",
            description="Django server-side HTTP 5xx error rate elevated. Warn: >1%  Critical: >5%",
            severity="Major",
            signalflow=f"""
total = data("django.request", {f}).count(over="2m")
errors = data("django.request", {f}, filter=filter("http.status_code", "5*")).count(over="2m")
error_pct = errors / total * 100
detect(when(error_pct > 5), lasting="2m").publish("Critical")
detect(when(error_pct > 1) and when(error_pct <= 5), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["django", "http", "errors"],
        ))

        # ── Request latency ───────────────────────────────────────────────────
        if baseline and baseline.latency_p99_ms:
            warn_t = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            desc = f"Django request latency anomaly. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms"
            threshold_type = "dynamic"
        else:
            warn_t, anomaly_t = 500, 1000
            desc = "Django request latency high. Warn: >500ms  Critical: >1000ms"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Django request latency high",
            description=desc,
            severity="Major",
            signalflow=f"""
A = data("django.request.duration", {f}).percentile(pct=99, over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence="high",
            tags=["django", "http", "latency"],
        ))

        # ── ORM slow queries ──────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Django ORM slow queries",
            description="Django ORM database query latency elevated — possible missing index or N+1. Warn: >100ms  Critical: >500ms",
            severity="Warning",
            signalflow=f"""
A = data("db.client.operation.duration", {f}).percentile(pct=95, over="5m")
detect(when(A > 500), lasting="5m").publish("Critical")
detect(when(A > 100) and when(A <= 500), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["django", "database", "orm"],
        ))

        # ── Template render time ──────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Django template render time high",
            description="Django template rendering unusually slow — check for complex template logic or missing cache",
            severity="Warning",
            signalflow=f"""
A = data("django.template.render.duration", {f}).mean(over="5m")
detect(when(A > 200), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="low",
            tags=["django", "template"],
        ))

        # ── DB connection errors ──────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Django database connection errors",
            description="Django database connection errors detected — possible DB unavailability or pool exhaustion",
            severity="Critical",
            signalflow=f"""
A = data("django.db.connection.errors", {f}).sum(over="2m")
detect(when(A > 5), lasting="2m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["django", "database", "connection"],
        ))

        return detectors
