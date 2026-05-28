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
A = data("process.runtime.cpython.thread_count", filter={f}).mean(over="5m")
detect(when(A > 200), lasting="5m").publish("Critical")
detect(when(A > 50) and when(A <= 200), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["python", "threads"],
            rationale=(
                "Thread leaks are a common Python issue in services using threading for I/O concurrency. "
                "Each thread consumes ~8MB stack by default; >200 threads typically indicates runaway "
                "thread creation (e.g. per-request threads never cleaned up). "
                "Metric: process.runtime.cpython.thread_count from OTel Python system-metrics instrumentation. "
                "Thresholds: 50 (warn) / 200 (critical) based on typical Python WSGI/ASGI thread pool sizes; "
                "tune to your thread pool max_workers setting. "
                "Source: Python threading docs; Gunicorn/uWSGI worker configuration best practices; "
                "CPython memory model documentation."
            ),
        ))

        # ── GC count rate ─────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Python GC collection rate high",
            description="Python GC collection rate elevated — high allocation pressure or memory leak. Warn: >10/min  Critical: >50/min",
            severity="Warning",
            signalflow=f"""
A = data("process.runtime.cpython.gc_count", filter={f}).mean(over="5m")
detect(when(A > 50), lasting="5m").publish("Critical")
detect(when(A > 10) and when(A <= 50), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["python", "gc"],
            rationale=(
                "Python's cyclic GC (generations 0/1/2) is triggered by allocation pressure. "
                "High GC rates indicate excessive object creation/retention, a precursor to memory "
                "leaks or OOM. Gen-0 collections are cheap; Gen-2 (full) collections cause latency "
                "spikes. Metric: process.runtime.cpython.gc_count from OTel Python runtime. "
                "Thresholds: 10/min (warn) / 50/min (critical) from Python memory profiling best "
                "practices; tune by checking which generation is spiking with gc.get_stats(). "
                "Source: CPython gc module docs; Python memory profiling guide (memory_profiler, "
                "tracemalloc); PyCon talks on Python GC internals."
            ),
        ))

        # ── Memory RSS ────────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Python process memory (RSS) high",
            description="Python process RSS memory high — possible memory leak. Warn: >512MB  Critical: >1GB",
            severity="Warning",
            signalflow=f"""
A = data("process.memory.rss", filter={f}).mean(over="5m")
detect(when(A > 1073741824), lasting="5m").publish("Critical")
detect(when(A > 536870912) and when(A <= 1073741824), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["python", "memory"],
            rationale=(
                "RSS (Resident Set Size) is actual physical memory used by the process. Steadily "
                "growing RSS without a ceiling indicates a memory leak. Python leaks commonly occur "
                "via global caches, event listeners never unregistered, or C extensions holding refs. "
                "Metric: process.memory.rss from OTel Python system-metrics (OTel semantic conventions). "
                "Thresholds: 512MB (warn) / 1GB (critical) — conservative defaults for containers; "
                "tune to 70%/90% of your container memory limit. "
                "Source: OTel Python system-metrics instrumentation docs; Python memory leak "
                "diagnosis guide (objgraph, tracemalloc); 12-factor app resource management."
            ),
        ))

        return detectors
