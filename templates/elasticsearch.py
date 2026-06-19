"""
Elasticsearch detector templates — cluster health, index/search latency,
JVM heap (ES-specific), unassigned shards, pending tasks, rejection rates.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class ElasticsearchTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Cluster status not green ──────────────────────────────────────────
        # 0=green, 1=yellow, 2=red
        detectors.append(DetectorTemplate(
            name=f"[{service}] Elasticsearch cluster status degraded",
            description="Elasticsearch cluster status is yellow (replica unassigned) or red (primary unassigned). Red = data loss risk.",
            severity="Critical",
            signalflow=f"""
A = data("elasticsearch.cluster.health", filter={f}).max(over="2m")
detect(when(A >= 2), lasting="2m").publish("Critical")
detect(when(A == 1), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["elasticsearch", "cluster"],
        ))

        # ── Unassigned shards ─────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Elasticsearch unassigned shards",
            description="Elasticsearch unassigned shards detected — data unavailability or node failure",
            severity="Major",
            signalflow=f"""
A = data("elasticsearch.cluster.shards.unassigned", filter={f}).max(over="5m")
detect(when(A > 0), lasting="5m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["elasticsearch", "shards"],
        ))

        # ── JVM heap (ES-specific, higher threshold than generic JVM) ─────────
        # ES recommends no more than 50% of available RAM, warn at 75% of heap
        detectors.append(DetectorTemplate(
            name=f"[{service}] Elasticsearch JVM heap usage high",
            description="Elasticsearch JVM heap usage high — above 75% risks GC pressure and node instability. Warn: >75%  Critical: >90%",
            severity="Major",
            signalflow=f"""
used = data("elasticsearch.node.jvm.memory.heap.used", filter={f}).mean(over="5m")
max_h = data("elasticsearch.node.jvm.memory.heap.max", filter={f}).mean(over="5m")
heap_pct = used / max_h * 100
detect(when(heap_pct > 90), lasting="5m").publish("Critical")
detect(when(heap_pct > 75) and when(heap_pct <= 90), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["elasticsearch", "jvm", "memory"],
        ))

        # ── Search latency ────────────────────────────────────────────────────
        if baseline and baseline.latency_p99_ms:
            w_sigma, c_sigma = baseline.sigma_multipliers()
            warn_t = round(baseline.latency_mean_ms + w_sigma * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + c_sigma * baseline.latency_stddev_ms, 1)
            desc = f"Elasticsearch search latency anomaly. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms"
            threshold_type = "dynamic"
        else:
            warn_t, anomaly_t = 200, 1000
            desc = "Elasticsearch search latency high. Warn: >200ms  Critical: >1000ms"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Elasticsearch search latency high",
            description=desc,
            severity="Major",
            signalflow=f"""
A = data("elasticsearch.node.search.latency", filter={f}).mean(over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence="high",
            tags=["elasticsearch", "search", "latency"],
        ))

        # ── Index latency ─────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Elasticsearch indexing latency high",
            description="Elasticsearch index operation latency elevated — possible disk I/O bottleneck or merge pressure. Warn: >50ms  Critical: >200ms",
            severity="Warning",
            signalflow=f"""
A = data("elasticsearch.node.index.latency", filter={f}).mean(over="5m")
detect(when(A > 200), lasting="5m").publish("Critical")
detect(when(A > 50) and when(A <= 200), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["elasticsearch", "indexing", "latency"],
        ))

        # ── Thread pool rejections ────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Elasticsearch thread pool rejections",
            description="Elasticsearch thread pool rejections — search or bulk queue saturated, requests being dropped",
            severity="Critical",
            signalflow=f"""
A = data("elasticsearch.node.thread_pool.rejected", filter={f}).sum(over="5m")
detect(when(A > 0), lasting="2m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["elasticsearch", "thread_pool"],
        ))

        # ── Pending tasks ─────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Elasticsearch pending cluster tasks high",
            description="Elasticsearch pending cluster tasks elevated — master node overloaded or stalled. Warn: >10  Critical: >50",
            severity="Warning",
            signalflow=f"""
A = data("elasticsearch.cluster.pending_tasks", filter={f}).max(over="5m")
detect(when(A > 50), lasting="5m").publish("Critical")
detect(when(A > 10) and when(A <= 50), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["elasticsearch", "cluster", "tasks"],
        ))

        return detectors
