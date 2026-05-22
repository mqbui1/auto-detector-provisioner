"""
.NET detector templates — GC, heap, exceptions, thread pool.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class DotNetTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        detectors.append(DetectorTemplate(
            name=f"[{service}] .NET GC collection rate high",
            description=".NET GC collection rate high — possible memory pressure. Warn: >10/min  Critical: >50/min",
            severity="Major",
            signalflow=f"""
A = data("process.runtime.dotnet.gc.collections.count", {f}).rate(over="5m")
detect(when(A > 50), lasting="5m").publish("Critical")
detect(when(A > 10) and when(A <= 50), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["dotnet", "gc"],
        ))

        detectors.append(DetectorTemplate(
            name=f"[{service}] .NET heap size high",
            description=".NET managed heap size elevated. Warn: >512MB  Critical: >1GB",
            severity="Major",
            signalflow=f"""
A = data("process.runtime.dotnet.gc.heap.size", {f}).mean(over="5m")
detect(when(A > 1073741824), lasting="5m").publish("Critical")
detect(when(A > 536870912) and when(A <= 1073741824), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["dotnet", "memory"],
        ))

        detectors.append(DetectorTemplate(
            name=f"[{service}] .NET exception rate high",
            description=".NET exception rate elevated — application error rate rising.",
            severity="Major",
            signalflow=f"""
A = data("process.runtime.dotnet.exceptions.count", {f}).rate(over="5m")
detect(when(A > 10), lasting="5m").publish("Critical")
detect(when(A > 1) and when(A <= 10), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["dotnet", "exceptions"],
        ))

        detectors.append(DetectorTemplate(
            name=f"[{service}] .NET thread pool queue depth high",
            description=".NET thread pool work items queued — thread pool may be saturated.",
            severity="Warning",
            signalflow=f"""
A = data("process.runtime.dotnet.thread_pool.queue.length", {f}).mean(over="5m")
detect(when(A > 100), lasting="5m").publish("Critical")
detect(when(A > 20) and when(A <= 100), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["dotnet", "threads"],
        ))

        return detectors
