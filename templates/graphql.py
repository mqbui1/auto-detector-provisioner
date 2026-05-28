"""
GraphQL detector templates — resolver error rate, query latency,
complexity/depth abuse, mutation error rate.
Works with Apollo Server, graphql-java, Strawberry, and any
OTel-instrumented GraphQL server emitting graphql.* metrics/spans.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class GraphQLTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Resolver error rate ───────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] GraphQL resolver error rate high",
            description="GraphQL resolver errors elevated — partial response failures or schema errors. Warn: >1%  Critical: >5%",
            severity="Major",
            signalflow=f"""
total = data("graphql.server.request.count", filter={f}).sum(over="2m")
errors = data("graphql.server.request.count", filter={f} and filter("graphql.error", "true")).sum(over="2m")
error_pct = errors / total * 100
detect(when(error_pct > 5), lasting="2m").publish("Critical")
detect(when(error_pct > 1) and when(error_pct <= 5), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["graphql", "errors"],
        ))

        # ── Query execution latency ───────────────────────────────────────────
        if baseline and baseline.latency_p99_ms:
            warn_t = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            desc = f"GraphQL query execution latency anomaly. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms"
            threshold_type = "dynamic"
        else:
            warn_t, anomaly_t = 500, 2000
            desc = "GraphQL query execution latency high. Warn: >500ms  Critical: >2000ms"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] GraphQL query execution latency high",
            description=desc,
            severity="Major",
            signalflow=f"""
A = data("graphql.server.request.duration", filter={f}).percentile(pct=99, over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence="high",
            tags=["graphql", "latency"],
        ))

        # ── Mutation error rate ───────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] GraphQL mutation error rate high",
            description="GraphQL mutation errors elevated — data write operations failing. Warn: >2%  Critical: >10%",
            severity="Major",
            signalflow=f"""
total = data("graphql.server.request.count", filter={f} and filter("graphql.operation.type", "mutation")).sum(over="5m")
errors = data("graphql.server.request.count", filter={f} and filter("graphql.operation.type", "mutation") and filter("graphql.error", "true")).sum(over="5m")
error_pct = errors / total * 100
detect(when(error_pct > 10), lasting="5m").publish("Critical")
detect(when(error_pct > 2) and when(error_pct <= 10), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["graphql", "mutation", "errors"],
        ))

        # ── Query depth / complexity abuse ────────────────────────────────────
        # Deep/complex queries indicate abuse or missing query limits
        detectors.append(DetectorTemplate(
            name=f"[{service}] GraphQL query complexity / depth abuse",
            description="GraphQL queries with excessive depth or complexity detected — potential denial-of-service or missing limits",
            severity="Warning",
            signalflow=f"""
A = data("graphql.server.request.depth", filter={f}).percentile(pct=95, over="5m")
detect(when(A > 15), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="low",
            tags=["graphql", "complexity", "security"],
        ))

        # ── N+1 resolver pattern ──────────────────────────────────────────────
        # Many resolvers firing per query is a classic GraphQL N+1 indicator
        detectors.append(DetectorTemplate(
            name=f"[{service}] GraphQL N+1 resolver pattern detected",
            description="GraphQL resolvers per request unusually high — possible N+1 query pattern without DataLoader",
            severity="Warning",
            signalflow=f"""
A = data("graphql.server.resolver.count", filter={f}).mean(over="5m")
detect(when(A > 100), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="low",
            tags=["graphql", "n+1", "performance"],
        ))

        return detectors
