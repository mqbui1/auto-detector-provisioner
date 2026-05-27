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
        # OTel Go runtime metrics carry service.name + deployment.environment,
        # not sf_service + sf_environment. Use OTel dimensions for runtime detectors.
        env_filter_rt = f'filter("deployment.environment", "{environment}") and ' if environment else ""
        svc_filter_rt = f'filter("service.name", "{service}")'
        f_rt = f"{env_filter_rt}{svc_filter_rt}"

        detectors = []

        # ── Goroutine count ───────────────────────────────────────────────────
        # go.goroutine.count is the stable OTel Go runtime metric name (SDK >=1.28)
        detectors.append(DetectorTemplate(
            name=f"[{service}] Go goroutine count high",
            description="Go goroutine count abnormally high — possible goroutine leak. Warn: >1000  Critical: >5000",
            severity="Major",
            signalflow=f"""
A = data("go.goroutine.count", {f_rt}).mean(over="5m")
detect(when(A > 5000), lasting="5m").publish("Critical")
detect(when(A > 1000) and when(A <= 5000), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["go", "goroutines"],
            rationale=(
                "Goroutine leaks are the most common silent memory/CPU bug in Go. A goroutine "
                "blocked on a channel, HTTP call, or DB query accumulates indefinitely without "
                "crashing the process — rising count and memory are the only symptoms. "
                "Normal Go microservices run 10–500 goroutines; >1000 sustained is almost always "
                "a leak. Metric: go.goroutine.count (stable OTel Go SDK name, replaces "
                "process.runtime.go.goroutines). Thresholds: 1000/5000 — tune to your service's "
                "normal steady-state goroutine count."
            ),
        ))

        # ── GC heap goal ──────────────────────────────────────────────────────
        # go.memory.gc.goal — target heap size for next GC; growing = heap pressure
        detectors.append(DetectorTemplate(
            name=f"[{service}] Go GC heap goal high",
            description="Go GC heap goal (next GC target size) elevated — heap is growing. Warn: >512MB  Critical: >1GB",
            severity="Warning",
            signalflow=f"""
A = data("go.memory.gc.goal", {f_rt}).mean(over="5m")
detect(when(A > 1073741824), lasting="5m").publish("Critical")
detect(when(A > 536870912) and when(A <= 1073741824), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["go", "gc"],
            rationale=(
                "go.memory.gc.goal is the heap size at which the next GC cycle fires. A "
                "continuously growing goal means the heap is expanding faster than GC reclaims it "
                "— a leading indicator of memory pressure before OOM. More reliable than 'heap "
                "used' because it reflects Go's GC pacing algorithm (GOGC). Metric: "
                "go.memory.gc.goal (stable OTel Go SDK, replaces "
                "process.runtime.go.gc.heap_goal). Thresholds: 512MB/1GB — tune to 50%/75% of "
                "your container memory limit."
            ),
        ))

        # ── Heap allocation rate (dynamic if baseline available) ───────────────
        if baseline and baseline.latency_mean_ms:
            detectors.append(DetectorTemplate(
                name=f"[{service}] Go heap allocation rate anomaly",
                description="Go heap allocation rate anomaly — possible memory pressure or allocation-heavy code path",
                severity="Warning",
                signalflow=f"""
A = data("go.memory.allocated", {f_rt}).rate(over="5m")
mean = data("go.memory.allocated", {f_rt}).mean(over="1h")
std = data("go.memory.allocated", {f_rt}).stddev(over="1h")
detect(when(A > mean + 3 * std), lasting="5m").publish("Anomaly")
detect(when(A > mean + 2 * std) and when(A <= mean + 3 * std), lasting="5m").publish("Warning")
""".strip(),
                threshold_type="dynamic",
                confidence="medium",
                tags=["go", "memory"],
                rationale=(
                    "Heap allocation rate spike (mean+2σ/3σ from baseline) indicates a code path "
                    "creating objects at an unusual rate — often triggered by a new traffic pattern "
                    "or a recent deploy introducing allocation-heavy logic. Dynamic thresholds "
                    "self-tune to this service's normal allocation rate. Metric: go.memory.allocated."
                ),
            ))

        return detectors
