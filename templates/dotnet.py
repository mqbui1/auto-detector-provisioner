"""
.NET detector templates — GC, heap, exceptions, thread pool.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class DotNetTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        # OTel .NET runtime metrics carry service.name + deployment.environment,
        # not sf_service + sf_environment. Use OTel dimensions for runtime detectors.
        env_filter_rt = f'filter("deployment.environment", "{environment}") and ' if environment else ""
        svc_filter_rt = f'filter("service.name", "{service}")'
        f_rt = f"{env_filter_rt}{svc_filter_rt}"

        detectors = []

        # dotnet.gc.collections — stable metric from OpenTelemetry.Instrumentation.Runtime >=1.7
        detectors.append(DetectorTemplate(
            name=f"[{service}] .NET GC collection rate high",
            description=".NET GC collection rate high — possible memory pressure. Warn: >10/min  Critical: >50/min",
            severity="Major",
            signalflow=f"""
A = data("dotnet.gc.collections", {f_rt}).rate(over="5m")
detect(when(A > 50), lasting="5m").publish("Critical")
detect(when(A > 10) and when(A <= 50), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["dotnet", "gc"],
            rationale=(
                "High .NET GC collection frequency, especially Gen 2 (full heap) collections, "
                "means the runtime is spending CPU reclaiming memory instead of doing work — "
                "a direct cause of latency spikes and throughput degradation. Gen 0/1 are cheap; "
                "Gen 2 is expensive. >10 Gen 2 collections/min is a known warning threshold in "
                ".NET performance engineering; >50/min indicates a GC storm. "
                "Metric: dotnet.gc.collections from OpenTelemetry.Instrumentation.Runtime >=1.7 "
                "(stable metric name, replaces process.runtime.dotnet.gc.collections.count). "
                "Source: Microsoft .NET performance docs; PerfView and dotnet-trace analysis guides."
            ),
        ))

        # dotnet.gc.last_collection.heap.size — managed heap size after last GC
        detectors.append(DetectorTemplate(
            name=f"[{service}] .NET heap size high",
            description=".NET managed heap size elevated. Warn: >512MB  Critical: >1GB",
            severity="Major",
            signalflow=f"""
A = data("dotnet.gc.last_collection.heap.size", {f_rt}).mean(over="5m")
detect(when(A > 1073741824), lasting="5m").publish("Critical")
detect(when(A > 536870912) and when(A <= 1073741824), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["dotnet", "memory"],
            rationale=(
                "Heap size after the last GC (post-collection live set) is the most accurate "
                "measure of actual retained memory — as opposed to allocated-but-not-yet-collected. "
                "A steadily growing post-GC heap means objects are being retained (memory leak or "
                "large unbounded cache). Thresholds are conservative for containerized microservices "
                "— tune to 50%/75% of your container memory limit. "
                "Metric: dotnet.gc.last_collection.heap.size (OTel .NET stable metric). "
                "Source: Microsoft .NET memory diagnostics guide; CLR GC internals documentation."
            ),
        ))

        # dotnet.exceptions — exception count rate
        detectors.append(DetectorTemplate(
            name=f"[{service}] .NET exception rate high",
            description=".NET exception rate elevated — application error rate rising.",
            severity="Major",
            signalflow=f"""
A = data("dotnet.exceptions", {f_rt}).rate(over="5m")
detect(when(A > 10), lasting="5m").publish("Critical")
detect(when(A > 1) and when(A <= 10), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["dotnet", "exceptions"],
            rationale=(
                ".NET exceptions are expensive (stack unwinding, heap allocation for the Exception "
                "object) and often indicate silent failures swallowed by catch blocks that never "
                "surface as HTTP errors. A rising exception rate that doesn't appear in the APM "
                "error rate is the classic 'hidden problem' pattern. Even 1/sec sustained is worth "
                "investigating. Metric: dotnet.exceptions (OTel .NET stable metric, replaces "
                "process.runtime.dotnet.exceptions.count). "
                "Source: Microsoft .NET exception handling performance docs; CLR exception cost analysis."
            ),
        ))

        # dotnet.thread_pool.queue.length — work items waiting for thread pool threads
        detectors.append(DetectorTemplate(
            name=f"[{service}] .NET thread pool queue depth high",
            description=".NET thread pool work items queued — thread pool may be saturated.",
            severity="Warning",
            signalflow=f"""
A = data("dotnet.thread_pool.queue.length", {f_rt}).mean(over="5m")
detect(when(A > 100), lasting="5m").publish("Critical")
detect(when(A > 20) and when(A <= 100), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["dotnet", "threads"],
            rationale=(
                "ASP.NET Core processes requests via the CLR thread pool. When the queue depth "
                "grows, incoming requests wait for a free thread — this is the saturation signal "
                "for .NET web services. >20 queued items means you are at capacity; >100 means "
                "requests are already experiencing significant latency from thread starvation. "
                "Often caused by synchronous blocking (.Result, .Wait()) inside async code paths. "
                "Metric: dotnet.thread_pool.queue.length (OTel .NET stable metric). "
                "Source: Microsoft ASP.NET Core performance best practices; Stephen Toub's async "
                "guidance; thread pool starvation analysis docs."
            ),
        ))

        return detectors
