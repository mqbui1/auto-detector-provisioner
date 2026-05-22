"""
Nginx / HAProxy detector templates — upstream error rate, worker saturation,
active connections, request rate drop, upstream response time.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class NginxTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── HTTP 5xx upstream error rate ──────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Nginx upstream 5xx error rate high",
            description="Nginx upstream 5xx error rate elevated — backend services returning errors. Warn: >1%  Critical: >5%",
            severity="Major",
            signalflow=f"""
total = data("nginx.requests", {f}).sum(over="2m")
errors = data("nginx.requests", {f}, filter=filter("status", "5*")).sum(over="2m")
error_pct = errors / total * 100
detect(when(error_pct > 5), lasting="2m").publish("Critical")
detect(when(error_pct > 1) and when(error_pct <= 5), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["nginx", "http", "errors"],
        ))

        # ── Worker connections saturation ─────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Nginx worker connections near limit",
            description="Nginx active connections near worker_connections limit — new connections may be refused. Warn: >80%  Critical: >95%",
            severity="Major",
            signalflow=f"""
active = data("nginx.connections.active", {f}).mean(over="2m")
accepted = data("nginx.connections.accepted", {f}).mean(over="2m")
conn_pct = active / accepted * 100
detect(when(conn_pct > 95), lasting="2m").publish("Critical")
detect(when(conn_pct > 80) and when(conn_pct <= 95), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["nginx", "connections", "saturation"],
        ))

        # ── Waiting (idle) connections high ───────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Nginx waiting connections high",
            description="Nginx idle (waiting) connections high — possible keepalive tuning issue or upstream slowness",
            severity="Warning",
            signalflow=f"""
A = data("nginx.connections.waiting", {f}).mean(over="5m")
detect(when(A > 1000), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["nginx", "connections"],
        ))

        # ── Upstream response time ────────────────────────────────────────────
        if baseline and baseline.latency_p99_ms:
            warn_t = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            desc = f"Nginx upstream response time anomaly. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms"
            threshold_type = "dynamic"
        else:
            warn_t, anomaly_t = 500, 2000
            desc = "Nginx upstream response time high. Warn: >500ms  Critical: >2000ms"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Nginx upstream response time high",
            description=desc,
            severity="Major",
            signalflow=f"""
A = data("nginx.upstream.response.time", {f}).percentile(pct=99, over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence="high",
            tags=["nginx", "upstream", "latency"],
        ))

        # ── Request rate drop ─────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Nginx request rate drop",
            description="Nginx incoming request rate dropped significantly — possible upstream DNS failure or load balancer misconfiguration",
            severity="Major",
            signalflow=f"""
A = data("nginx.requests", {f}).rate(over="5m")
hist = data("nginx.requests", {f}).mean(over="1h")
detect(when(A < hist * 0.3), lasting="5m").publish("Critical")
detect(when(A < hist * 0.5) and when(A >= hist * 0.3), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="dynamic",
            confidence="medium",
            tags=["nginx", "request_rate"],
        ))

        # ── 4xx rate (bad gateway / client errors) ────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Nginx 4xx error rate spike",
            description="Nginx 4xx client error rate spike — possible bad deploy sending malformed requests or auth misconfiguration. Warn: >5%  Critical: >20%",
            severity="Warning",
            signalflow=f"""
total = data("nginx.requests", {f}).sum(over="5m")
client_errors = data("nginx.requests", {f}, filter=filter("status", "4*")).sum(over="5m")
error_pct = client_errors / total * 100
detect(when(error_pct > 20), lasting="5m").publish("Critical")
detect(when(error_pct > 5) and when(error_pct <= 20), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["nginx", "http", "4xx"],
        ))

        return detectors
