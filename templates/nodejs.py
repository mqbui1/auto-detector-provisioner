"""
Node.js detector templates — heap, event loop lag, libuv thread pool.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class NodeJSTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        detectors.append(DetectorTemplate(
            name=f"[{service}] Node.js heap usage high",
            description="Node.js heap usage near limit — possible memory leak. Warn: >75%  Critical: >90%",
            severity="Major",
            signalflow=f"""
used = data("process.runtime.nodejs.memory.heap.used", {f}).mean(over="5m")
total = data("process.runtime.nodejs.memory.heap.total", {f}).mean(over="5m")
heap_pct = used / total * 100
detect(when(heap_pct > 90), lasting="5m").publish("Critical")
detect(when(heap_pct > 75) and when(heap_pct <= 90), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["nodejs", "memory"],
        ))

        detectors.append(DetectorTemplate(
            name=f"[{service}] Node.js event loop lag high",
            description="Node.js event loop lag elevated — I/O blocking or CPU-intensive work on main thread. Warn: >100ms  Critical: >500ms",
            severity="Major",
            signalflow=f"""
A = data("process.runtime.nodejs.eventloop.lag.mean", {f}).mean(over="5m")
detect(when(A > 500), lasting="5m").publish("Critical")
detect(when(A > 100) and when(A <= 500), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["nodejs", "event_loop"],
        ))

        detectors.append(DetectorTemplate(
            name=f"[{service}] Node.js active handles high",
            description="Node.js active handle count abnormally high — possible handle leak.",
            severity="Warning",
            signalflow=f"""
A = data("process.runtime.nodejs.active_handles", {f}).mean(over="5m")
detect(when(A > 1000), lasting="10m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["nodejs", "handles"],
        ))

        return detectors
