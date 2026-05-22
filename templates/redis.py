"""
Redis detector templates — hit rate, evictions, connection pool, latency.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class RedisTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Cache hit rate drop ───────────────────────────────────────────────
        # Best practice: warn <80%, critical <50%
        detectors.append(DetectorTemplate(
            name=f"[{service}] Redis cache hit rate low",
            description="Redis cache hit rate dropped — possible cache thrashing or cold cache. Warn: <80%  Critical: <50%",
            severity="Warning",
            signalflow=f"""
hits = data("redis.keyspace_hits", {f}).sum(over="5m")
misses = data("redis.keyspace_misses", {f}).sum(over="5m")
hit_rate = hits / (hits + misses) * 100
detect(when(hit_rate < 50), lasting="5m").publish("Critical")
detect(when(hit_rate < 80) and when(hit_rate >= 50), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["redis", "cache"],
        ))

        # ── Eviction rate spike ───────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Redis eviction rate high",
            description="Redis evicting keys at high rate — maxmemory limit may be too low.",
            severity="Major",
            signalflow=f"""
A = data("redis.evicted_keys", {f}).rate(over="5m")
detect(when(A > 100), lasting="5m").publish("Critical")
detect(when(A > 10) and when(A <= 100), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["redis", "memory", "eviction"],
        ))

        # ── Connection count ──────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Redis connection count high",
            description="Redis connected clients near limit. Warn: >80%  Critical: >95%",
            severity="Major",
            signalflow=f"""
connected = data("redis.connected_clients", {f}).mean(over="5m")
max_clients = data("redis.maxclients", {f}).mean(over="5m")
conn_pct = connected / max_clients * 100
detect(when(conn_pct > 95), lasting="2m").publish("Critical")
detect(when(conn_pct > 80) and when(conn_pct <= 95), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["redis", "connections"],
        ))

        # ── Latency p99 ───────────────────────────────────────────────────────
        if baseline and baseline.latency_mean_ms and baseline.latency_stddev_ms and baseline.is_reliable():
            warn_t = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            threshold_type = "dynamic"
            confidence = "high"
        else:
            warn_t = 10     # 10ms
            anomaly_t = 50  # 50ms
            threshold_type = "fixed"
            confidence = "medium"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Redis command latency high",
            description=f"Redis command latency elevated. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms",
            severity="Warning",
            signalflow=f"""
A = data("redis.latency", {f}).mean(over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence=confidence,
            tags=["redis", "latency"],
        ))

        # ── Memory usage ──────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Redis memory usage high",
            description="Redis memory usage near maxmemory limit. Warn: >75%  Critical: >90%",
            severity="Major",
            signalflow=f"""
used = data("redis.used_memory", {f}).mean(over="5m")
max_mem = data("redis.maxmemory", {f}).mean(over="5m")
mem_pct = used / max_mem * 100
detect(when(mem_pct > 90), lasting="5m").publish("Critical")
detect(when(mem_pct > 75) and when(mem_pct <= 90), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["redis", "memory"],
        ))

        return detectors
