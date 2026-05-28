"""
Database detector templates — PostgreSQL, MySQL, MongoDB connection pools,
slow queries, deadlocks.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class DatabaseTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None, db_type: str = "") -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── DB span latency (APM-based) ───────────────────────────────────────
        if baseline and baseline.latency_mean_ms and baseline.latency_stddev_ms and baseline.is_reliable():
            warn_t = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            threshold_type = "dynamic"
            confidence = "high"
        else:
            warn_t = 500    # 500ms
            anomaly_t = 2000  # 2s
            threshold_type = "fixed"
            confidence = "medium"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Database query latency high",
            description=f"DB query latency elevated (APM span-based). Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms",
            severity="Major",
            signalflow=f"""
A = data("service.request.duration", filter={f} and filter("span.kind", "client") and filter("db.system", "*")).mean(over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence=confidence,
            tags=["database", "latency"],
        ))

        # ── PostgreSQL-specific detectors ─────────────────────────────────────
        if not db_type or db_type == "postgresql":
            detectors.append(DetectorTemplate(
                name=f"[{service}] PostgreSQL connection pool saturation",
                description="PostgreSQL active connections near max_connections limit. Warn: >80%  Critical: >95%",
                severity="Major",
                signalflow=f"""
active = data("postgresql.connections", filter={f} and filter("state", "active")).sum(over="5m")
max_conn = data("postgresql.connections.max", filter={f}).mean(over="5m")
conn_pct = active / max_conn * 100
detect(when(conn_pct > 95), lasting="2m").publish("Critical")
detect(when(conn_pct > 80) and when(conn_pct <= 95), lasting="2m").publish("Warning")
""".strip(),
                threshold_type="fixed",
                confidence="high",
                tags=["postgresql", "connection_pool"],
            ))
            detectors.append(DetectorTemplate(
                name=f"[{service}] PostgreSQL deadlocks detected",
                description="PostgreSQL deadlocks occurring — review transaction ordering and locking patterns.",
                severity="Major",
                signalflow=f"""
A = data("postgresql.deadlocks", filter={f}).mean(over="5m")
detect(when(A > 0), lasting="5m").publish("Warning")
detect(when(A > 1), lasting="5m").publish("Critical")
""".strip(),
                threshold_type="fixed",
                confidence="high",
                tags=["postgresql", "deadlocks"],
            ))

        # ── MySQL-specific detectors ──────────────────────────────────────────
        if not db_type or db_type == "mysql":
            detectors.append(DetectorTemplate(
                name=f"[{service}] MySQL connection pool saturation",
                description="MySQL threads connected near max_connections. Warn: >80%  Critical: >95%",
                severity="Major",
                signalflow=f"""
connected = data("mysql.threads", filter={f} and filter("kind", "connected")).mean(over="5m")
max_conn = data("mysql.connections.max", filter={f}).mean(over="5m")
conn_pct = connected / max_conn * 100
detect(when(conn_pct > 95), lasting="2m").publish("Critical")
detect(when(conn_pct > 80) and when(conn_pct <= 95), lasting="2m").publish("Warning")
""".strip(),
                threshold_type="fixed",
                confidence="high",
                tags=["mysql", "connection_pool"],
            ))

        # ── MongoDB-specific detectors ────────────────────────────────────────
        if not db_type or db_type == "mongodb":
            detectors.append(DetectorTemplate(
                name=f"[{service}] MongoDB operation latency high",
                description="MongoDB operation latency elevated. Warn: >100ms  Critical: >500ms",
                severity="Major",
                signalflow=f"""
A = data("mongodb.operation.latency.time", filter={f}).mean(over="5m")
detect(when(A > 500), lasting="5m").publish("Critical")
detect(when(A > 100) and when(A <= 500), lasting="5m").publish("Warning")
""".strip(),
                threshold_type="fixed",
                confidence="high",
                tags=["mongodb", "latency"],
            ))

        # ── N+1 query detection (ORM heuristic) ──────────────────────────────
        # High DB span count per service request → likely N+1
        detectors.append(DetectorTemplate(
            name=f"[{service}] Possible N+1 query pattern detected",
            description="Unusually high DB span count per request — possible ORM N+1 query pattern.",
            severity="Warning",
            signalflow=f"""
db_spans = data("service.request.count", filter={f} and filter("span.kind", "client") and filter("db.system", "*")).sum(over="5m")
total_reqs = data("service.request.count", filter={f} and filter("span.kind", "server")).sum(over="5m")
ratio = db_spans / total_reqs
detect(when(ratio > 10), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="low",
            tags=["database", "orm", "n+1"],
        ))

        return detectors
