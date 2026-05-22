"""
Celery detector templates — task failure rate, queue depth, task duration,
worker count, retry rate, task timeout.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class CeleryTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Task failure rate ─────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Celery task failure rate high",
            description="Celery task failure rate elevated — background jobs failing. Warn: >2%  Critical: >10%",
            severity="Major",
            signalflow=f"""
total = data("celery.task.total", {f}).sum(over="5m")
failed = data("celery.task.total", {f}, filter=filter("state", "FAILURE")).sum(over="5m")
failure_pct = failed / total * 100
detect(when(failure_pct > 10), lasting="5m").publish("Critical")
detect(when(failure_pct > 2) and when(failure_pct <= 10), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["celery", "tasks", "errors"],
        ))

        # ── Queue depth ───────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Celery queue depth high",
            description="Celery task queue depth elevated — workers not keeping up with task production. Warn: >100  Critical: >1000",
            severity="Major",
            signalflow=f"""
A = data("celery.queue.length", {f}).max(over="5m")
detect(when(A > 1000), lasting="5m").publish("Critical")
detect(when(A > 100) and when(A <= 1000), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["celery", "queue"],
        ))

        # ── Worker count drop ─────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Celery worker count dropped",
            description="Celery worker count dropped — tasks will queue with no processing",
            severity="Critical",
            signalflow=f"""
A = data("celery.worker.online", {f}).sum(over="2m")
detect(when(A < 1), lasting="2m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["celery", "workers"],
        ))

        # ── Task execution duration anomaly ───────────────────────────────────
        if baseline and baseline.latency_mean_ms:
            warn_t = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            desc = f"Celery task execution duration anomaly. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms"
            threshold_type = "dynamic"
        else:
            warn_t, anomaly_t = 30000, 120000
            desc = "Celery task execution duration high. Warn: >30s  Critical: >120s"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Celery task execution duration high",
            description=desc,
            severity="Warning",
            signalflow=f"""
A = data("celery.task.duration", {f}).percentile(pct=95, over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence="high",
            tags=["celery", "tasks", "latency"],
        ))

        # ── Retry rate ────────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Celery task retry rate elevated",
            description="Celery task retry rate elevated — tasks failing transiently (network errors, rate limits, etc.)",
            severity="Warning",
            signalflow=f"""
total = data("celery.task.total", {f}).sum(over="5m")
retried = data("celery.task.total", {f}, filter=filter("state", "RETRY")).sum(over="5m")
retry_pct = retried / total * 100
detect(when(retry_pct > 10), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["celery", "tasks", "retries"],
        ))

        # ── Task timeout ──────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Celery task timeout rate elevated",
            description="Celery tasks being hard-killed by timeout — task logic needs optimization or timeout needs tuning",
            severity="Major",
            signalflow=f"""
A = data("celery.task.timeout", {f}).sum(over="5m")
detect(when(A > 5), lasting="5m").publish("Warning")
detect(when(A > 20), lasting="5m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["celery", "tasks", "timeout"],
        ))

        return detectors
