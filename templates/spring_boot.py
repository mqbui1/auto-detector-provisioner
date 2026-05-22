"""
Spring Boot detector templates — HTTP request metrics, actuator health,
slow startup, circuit breakers, scheduler, Feign client errors.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class SpringBootTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── HTTP 5xx rate ─────────────────────────────────────────────────────
        # spring.http.server.requests with outcome=SERVER_ERROR
        detectors.append(DetectorTemplate(
            name=f"[{service}] Spring Boot HTTP 5xx error rate high",
            description="Spring Boot server-side HTTP 5xx error rate elevated. Warn: >1%  Critical: >5%",
            severity="Major",
            signalflow=f"""
total = data("spring.http.server.requests", {f}).count(over="2m")
errors = data("spring.http.server.requests", {f}, filter=filter("outcome", "SERVER_ERROR")).count(over="2m")
error_pct = errors / total * 100
detect(when(error_pct > 5), lasting="2m").publish("Critical")
detect(when(error_pct > 1) and when(error_pct <= 5), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["spring_boot", "http", "errors"],
        ))

        # ── HTTP request latency ──────────────────────────────────────────────
        # Dynamic if baseline, else fixed
        if baseline and baseline.latency_p99_ms:
            warn_t = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            desc = f"Spring Boot HTTP request latency anomaly. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms"
            threshold_type = "dynamic"
        else:
            warn_t, anomaly_t = 500, 1000
            desc = "Spring Boot HTTP request latency high. Warn: >500ms  Critical: >1000ms"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Spring Boot HTTP request latency high",
            description=desc,
            severity="Major",
            signalflow=f"""
A = data("spring.http.server.requests", {f}).percentile(pct=99, over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence="high",
            tags=["spring_boot", "http", "latency"],
        ))

        # ── Actuator health check failing ─────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Spring Boot actuator health degraded",
            description="Spring Boot actuator health endpoint reporting non-UP status for sustained period",
            severity="Critical",
            signalflow=f"""
A = data("spring.boot.actuator.health", {f}).mean(over="2m")
detect(when(A < 1), lasting="2m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["spring_boot", "health"],
        ))

        # ── Scheduler task failures ───────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Spring Boot scheduled task failures",
            description="Spring Boot @Scheduled tasks failing — background job errors detected",
            severity="Warning",
            signalflow=f"""
A = data("spring.task.scheduled.execution.failed", {f}).sum(over="5m")
detect(when(A > 3), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["spring_boot", "scheduler"],
        ))

        # ── Feign / REST client error rate ────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Spring Boot outbound HTTP client error rate",
            description="Spring Boot RestTemplate/Feign outbound HTTP 5xx error rate elevated. Warn: >2%  Critical: >10%",
            severity="Major",
            signalflow=f"""
total = data("http.client.requests", {f}).count(over="2m")
errors = data("http.client.requests", {f}, filter=filter("outcome", "SERVER_ERROR")).count(over="2m")
error_pct = errors / total * 100
detect(when(error_pct > 10), lasting="2m").publish("Critical")
detect(when(error_pct > 2) and when(error_pct <= 10), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["spring_boot", "http", "client", "errors"],
        ))

        return detectors
