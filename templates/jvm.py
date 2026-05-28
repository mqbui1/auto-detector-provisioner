"""
JVM detector templates — heap, GC, threads, class loading.
Applies to Java services (Spring Boot, Quarkus, Micronaut, etc.)
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class JVMTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Heap usage % ──────────────────────────────────────────────────────
        # Best practice: warn >75%, critical >90%
        detectors.append(DetectorTemplate(
            name=f"[{service}] JVM heap usage high",
            description="JVM heap usage exceeds safe operating range. Warn: >75%  Critical: >90%",
            severity="Major",
            signalflow=f"""
used = data("jvm.memory.heap.used", filter={f}).mean(over="5m")
max_heap = data("jvm.memory.heap.max", filter={f}).mean(over="5m")
heap_pct = used / max_heap * 100
detect(when(heap_pct > 90), lasting="5m").publish("Critical")
detect(when(heap_pct > 75) and when(heap_pct <= 90), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["jvm", "memory"],
        ))

        # ── GC pause time ─────────────────────────────────────────────────────
        # Best practice: warn >200ms mean GC pause, critical >500ms
        detectors.append(DetectorTemplate(
            name=f"[{service}] JVM GC pause time high",
            description="JVM GC pause time exceeds threshold. Warn: >200ms  Critical: >500ms",
            severity="Major",
            signalflow=f"""
A = data("jvm.gc.pause", filter={f}).mean(over="5m")
detect(when(A > 500), lasting="5m").publish("Critical")
detect(when(A > 200) and when(A <= 500), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["jvm", "gc"],
        ))

        # ── GC collection rate ────────────────────────────────────────────────
        # Dynamic if baseline available, else fixed
        if baseline and "jvm.gc.collections.count" in baseline.metrics:
            m = baseline.metrics["jvm.gc.collections.count"]
            if m.is_reliable():
                warn_t = round(m.warn_threshold(2.0), 2)
                anomaly_t = round(m.anomaly_threshold(3.0), 2)
                detectors.append(DetectorTemplate(
                    name=f"[{service}] JVM GC collection rate anomaly",
                    description=f"JVM GC collection rate anomaly. Baseline mean: {m.mean:.2f}/min",
                    severity="Warning",
                    signalflow=f"""
A = data("jvm.gc.collections.count", filter={f}).mean(over="1m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
                    threshold_type="dynamic",
                    confidence="high",
                    tags=["jvm", "gc"],
                ))

        # ── Thread count ──────────────────────────────────────────────────────
        # Best practice: warn >200 threads, critical >500
        detectors.append(DetectorTemplate(
            name=f"[{service}] JVM thread count high",
            description="JVM thread count abnormally high — possible thread leak. Warn: >200  Critical: >500",
            severity="Major",
            signalflow=f"""
A = data("jvm.threads.count", filter={f}).mean(over="5m")
detect(when(A > 500), lasting="5m").publish("Critical")
detect(when(A > 200) and when(A <= 500), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["jvm", "threads"],
        ))

        # ── Non-heap / metaspace ──────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] JVM non-heap (metaspace) usage high",
            description="JVM metaspace growing — possible class loader leak. Warn: >256MB  Critical: >512MB",
            severity="Warning",
            signalflow=f"""
A = data("jvm.memory.nonheap.used", filter={f}).mean(over="5m")
detect(when(A > 536870912), lasting="10m").publish("Critical")
detect(when(A > 268435456) and when(A <= 536870912), lasting="10m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["jvm", "memory", "metaspace"],
        ))

        # ── Spring Boot Hikari connection pool (if spring_boot detected) ──────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Hikari connection pool exhaustion",
            description="Spring Boot Hikari DB connection pool near exhaustion. Warn: >80%  Critical: >95%",
            severity="Major",
            signalflow=f"""
active = data("hikaricp.connections.active", filter={f}).mean(over="2m")
max_pool = data("hikaricp.connections.max", filter={f}).mean(over="2m")
pool_pct = active / max_pool * 100
detect(when(pool_pct > 95), lasting="2m").publish("Critical")
detect(when(pool_pct > 80) and when(pool_pct <= 95), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["jvm", "spring_boot", "database", "connection_pool"],
        ))

        # ── Tomcat thread exhaustion ──────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Tomcat thread pool exhaustion",
            description="Spring Boot Tomcat thread pool near exhaustion — HTTP requests may queue. Warn: >80%  Critical: >95%",
            severity="Major",
            signalflow=f"""
busy = data("tomcat.threads.busy", filter={f}).mean(over="2m")
max_t = data("tomcat.threads.config.max", filter={f}).mean(over="2m")
thread_pct = busy / max_t * 100
detect(when(thread_pct > 95), lasting="2m").publish("Critical")
detect(when(thread_pct > 80) and when(thread_pct <= 95), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["jvm", "spring_boot", "threads", "tomcat"],
        ))

        return detectors
