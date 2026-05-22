"""
Cassandra detector templates — read/write latency, compaction backlog,
dropped mutations, pending tasks, heap usage, hints.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class CassandraTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Read latency ──────────────────────────────────────────────────────
        if baseline and baseline.latency_p99_ms:
            warn_t = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            desc = f"Cassandra read latency anomaly. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms"
            threshold_type = "dynamic"
        else:
            warn_t, anomaly_t = 10, 50
            desc = "Cassandra read latency high. Warn: >10ms  Critical: >50ms"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Cassandra read latency high",
            description=desc,
            severity="Major",
            signalflow=f"""
A = data("cassandra.client.request.latency", {f}, filter=filter("operation", "read")).percentile(pct=99, over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence="high",
            tags=["cassandra", "read", "latency"],
        ))

        # ── Write latency ─────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Cassandra write latency high",
            description="Cassandra write latency high — possible compaction pressure or disk saturation. Warn: >10ms  Critical: >50ms",
            severity="Major",
            signalflow=f"""
A = data("cassandra.client.request.latency", {f}, filter=filter("operation", "write")).percentile(pct=99, over="5m")
detect(when(A > 50), lasting="5m").publish("Critical")
detect(when(A > 10) and when(A <= 50), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["cassandra", "write", "latency"],
        ))

        # ── Dropped mutations ─────────────────────────────────────────────────
        # Dropped mutations = data loss risk
        detectors.append(DetectorTemplate(
            name=f"[{service}] Cassandra dropped mutations detected",
            description="Cassandra dropped mutations — write requests dropped due to overload. Data loss risk.",
            severity="Critical",
            signalflow=f"""
A = data("cassandra.dropped.messages", {f}, filter=filter("message_type", "MUTATION")).sum(over="5m")
detect(when(A > 0), lasting="2m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["cassandra", "dropped", "mutations"],
        ))

        # ── Compaction pending tasks ──────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Cassandra compaction backlog high",
            description="Cassandra compaction pending tasks elevated — read performance will degrade as SSTables accumulate. Warn: >30  Critical: >100",
            severity="Warning",
            signalflow=f"""
A = data("cassandra.compaction.tasks.pending", {f}).max(over="5m")
detect(when(A > 100), lasting="5m").publish("Critical")
detect(when(A > 30) and when(A <= 100), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["cassandra", "compaction"],
        ))

        # ── JVM heap ──────────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Cassandra JVM heap usage high",
            description="Cassandra JVM heap usage high — GC pressure will impact latency. Warn: >70%  Critical: >85%",
            severity="Major",
            signalflow=f"""
used = data("cassandra.jvm.memory.heap.used", {f}).mean(over="5m")
max_h = data("cassandra.jvm.memory.heap.max", {f}).mean(over="5m")
heap_pct = used / max_h * 100
detect(when(heap_pct > 85), lasting="5m").publish("Critical")
detect(when(heap_pct > 70) and when(heap_pct <= 85), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["cassandra", "jvm", "memory"],
        ))

        # ── Hints accumulating ────────────────────────────────────────────────
        # Hinted handoff = writes buffered for a down node; too many = node was down a long time
        detectors.append(DetectorTemplate(
            name=f"[{service}] Cassandra hinted handoff accumulating",
            description="Cassandra hints accumulating — a node was unreachable and writes are being buffered. Node may be down.",
            severity="Warning",
            signalflow=f"""
A = data("cassandra.storage.hints.on_disk", {f}).max(over="5m")
detect(when(A > 1000), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["cassandra", "hints", "availability"],
        ))

        # ── Read errors ───────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Cassandra read errors elevated",
            description="Cassandra read errors elevated — unavailable or timeout errors on reads",
            severity="Major",
            signalflow=f"""
A = data("cassandra.client.request.errors", {f}, filter=filter("operation", "read")).sum(over="5m")
detect(when(A > 10), lasting="5m").publish("Critical")
detect(when(A > 1) and when(A <= 10), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["cassandra", "errors"],
        ))

        return detectors
