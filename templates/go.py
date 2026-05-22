"""
Go runtime detector templates — goroutine count, GC pause, heap allocation rate,
memory usage. Uses OTel Go runtime instrumentation metrics
(go.opentelemetry.io/contrib/instrumentation/runtime).
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class GoTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Goroutine count ───────────────────────────────────────────────────
        # High goroutine count = goroutine leak
        detectors.append(DetectorTemplate(
            name=f"[{service}] Go goroutine count high",
            description="Go goroutine count abnormally high — possible goroutine leak. Warn: >1000  Critical: >5000",
            severity="Major",
            signalflow=f"""
A = data("process.runtime.go.goroutines", {f}).mean(over="5m")
detect(when(A > 5000), lasting="5m").publish("Critical")
detect(when(A > 1000) and when(A <= 5000), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["go", "goroutines"],
        ))

        # ── GC pause ──────────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Go GC pause time high",
            description="Go GC pause time elevated — consider GC tuning or reducing allocation rate. Warn: >10ms  Critical: >50ms",
            severity="Warning",
            signalflow=f"""
A = data("process.runtime.go.gc.pause_ns", {f}).mean(over="5m") / 1000000
detect(when(A > 50), lasting="5m").publish("Critical")
detect(when(A > 10) and when(A <= 50), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["go", "gc"],
        ))

        # ── Heap allocation ───────────────────────────────────────────────────
        if baseline and baseline.latency_mean_ms:
            # Use dynamic for heap alloc rate if baseline available
            detectors.append(DetectorTemplate(
                name=f"[{service}] Go heap allocation rate anomaly",
                description="Go heap allocation rate anomaly — possible memory pressure or allocation-heavy code path",
                severity="Warning",
                signalflow=f"""
A = data("process.runtime.go.mem.heap_alloc", {f}).rate(over="5m")
mean = data("process.runtime.go.mem.heap_alloc", {f}).mean(over="1h")
std = data("process.runtime.go.mem.heap_alloc", {f}).stddev(over="1h")
detect(when(A > mean + 3 * std), lasting="5m").publish("Anomaly")
detect(when(A > mean + 2 * std) and when(A <= mean + 3 * std), lasting="5m").publish("Warning")
""".strip(),
                threshold_type="dynamic",
                confidence="medium",
                tags=["go", "memory"],
            ))

        # ── Heap in-use ───────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Go heap in-use high",
            description="Go heap in-use memory growing — check for memory leaks or large object retention. Warn: >512MB  Critical: >1GB",
            severity="Warning",
            signalflow=f"""
A = data("process.runtime.go.mem.heap_inuse", {f}).mean(over="5m")
detect(when(A > 1073741824), lasting="5m").publish("Critical")
detect(when(A > 536870912) and when(A <= 1073741824), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["go", "memory"],
        ))

        return detectors
