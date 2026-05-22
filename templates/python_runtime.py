"""
Python runtime detector templates — GC collections, thread count,
memory (RSS), open file descriptors. Uses OTel Python runtime metrics
(opentelemetry-instrumentation-system-metrics or similar).
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class PythonTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Thread count ──────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Python thread count high",
            description="Python thread count abnormally high — possible thread leak. Warn: >50  Critical: >200",
            severity="Major",
            signalflow=f"""
A = data("process.runtime.cpython.thread_count", {f}).mean(over="5m")
detect(when(A > 200), lasting="5m").publish("Critical")
detect(when(A > 50) and when(A <= 200), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["python", "threads"],
        ))

        # ── GC count rate ─────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Python GC collection rate high",
            description="Python GC collection rate elevated — high allocation pressure or memory leak. Warn: >10/min  Critical: >50/min",
            severity="Warning",
            signalflow=f"""
A = data("process.runtime.cpython.gc_count", {f}).rate(over="5m")
detect(when(A > 50), lasting="5m").publish("Critical")
detect(when(A > 10) and when(A <= 50), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["python", "gc"],
        ))

        # ── Memory RSS ────────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Python process memory (RSS) high",
            description="Python process RSS memory high — possible memory leak. Warn: >512MB  Critical: >1GB",
            severity="Warning",
            signalflow=f"""
A = data("process.memory.rss", {f}).mean(over="5m")
detect(when(A > 1073741824), lasting="5m").publish("Critical")
detect(when(A > 536870912) and when(A <= 1073741824), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["python", "memory"],
        ))

        # ── CPU utilization ───────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Python process CPU utilization high",
            description="Python process CPU utilization high — possible CPU-bound code or infinite loop. Warn: >80%  Critical: >95%",
            severity="Warning",
            signalflow=f"""
A = data("process.cpu.utilization", {f}).mean(over="5m")
detect(when(A > 95), lasting="5m").publish("Critical")
detect(when(A > 80) and when(A <= 95), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["python", "cpu"],
        ))

        return detectors
