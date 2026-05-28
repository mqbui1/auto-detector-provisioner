"""
HTTP pattern detector templates — cross-framework patterns that apply to any
HTTP service regardless of stack: 429 rate limiting, 401/403 auth failures,
batch/cron job anomalies, observability quality (metric staleness, trace gaps).
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class HTTPPatternsTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── 429 Rate limit spike ──────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] HTTP 429 rate limit exceeded spike",
            description="HTTP 429 Too Many Requests rate elevated — possible client abuse, quota misconfiguration, or traffic spike exceeding limits. Warn: >2%  Critical: >10%",
            severity="Warning",
            signalflow=f"""
total = data("service.request.count", filter={f}).sum(over="5m")
rate_limited = data("service.request.count", filter={f} and filter("http.status_code", "429")).sum(over="5m")
pct = rate_limited / total * 100
detect(when(pct > 10), lasting="5m").publish("Critical")
detect(when(pct > 2) and when(pct <= 10), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["http", "rate_limiting", "429"],
        ))

        # ── 401 Auth failure spike ────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] HTTP 401 authentication failure spike",
            description="HTTP 401 Unauthorized rate elevated — expired tokens, broken auth middleware, or credential rotation issue. Warn: >5%  Critical: >20%",
            severity="Major",
            signalflow=f"""
total = data("service.request.count", filter={f}).sum(over="5m")
auth_fails = data("service.request.count", filter={f} and filter("http.status_code", "401")).sum(over="5m")
pct = auth_fails / total * 100
detect(when(pct > 20), lasting="5m").publish("Critical")
detect(when(pct > 5) and when(pct <= 20), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["http", "auth", "401"],
        ))

        # ── 403 Authorization failure spike ──────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] HTTP 403 authorization failure spike",
            description="HTTP 403 Forbidden rate elevated — RBAC misconfiguration, certificate issues, or IP allowlist change. Warn: >2%  Critical: >10%",
            severity="Major",
            signalflow=f"""
total = data("service.request.count", filter={f}).sum(over="5m")
authz_fails = data("service.request.count", filter={f} and filter("http.status_code", "403")).sum(over="5m")
pct = authz_fails / total * 100
detect(when(pct > 10), lasting="5m").publish("Critical")
detect(when(pct > 2) and when(pct <= 10), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["http", "authz", "403"],
        ))

        # ── 502/503/504 gateway errors ────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] HTTP gateway error rate (502/503/504)",
            description="HTTP 502/503/504 gateway errors elevated — upstream unavailable or timing out. Warn: >1%  Critical: >5%",
            severity="Major",
            signalflow=f"""
total = data("service.request.count", filter={f}).sum(over="2m")
gateway_errors = data("service.request.count", filter={f} and filter("http.status_code", "502") or filter("http.status_code", "503") or filter("http.status_code", "504")).sum(over="2m")
pct = gateway_errors / total * 100
detect(when(pct > 5), lasting="2m").publish("Critical")
detect(when(pct > 1) and when(pct <= 5), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["http", "gateway", "502", "503", "504"],
        ))

        return detectors


class BatchJobTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Batch job failure ─────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Batch job failure detected",
            description="Batch / cron job reported a failure status — scheduled job did not complete successfully",
            severity="Major",
            signalflow=f"""
A = data("batch.job.failed_count", filter={f}).sum(over="10m")
detect(when(A > 0), lasting="5m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["batch", "cron", "jobs"],
        ))

        # ── Batch job duration anomaly ────────────────────────────────────────
        if baseline and baseline.latency_mean_ms:
            warn_t = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            desc = f"Batch job duration anomaly. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms"
            threshold_type = "dynamic"
        else:
            warn_t, anomaly_t = 300000, 900000
            desc = "Batch job duration high. Warn: >5min  Critical: >15min"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Batch job duration anomaly",
            description=desc,
            severity="Warning",
            signalflow=f"""
A = data("batch.job.duration", filter={f}).mean(over="10m")
detect(when(A > {anomaly_t}), lasting="10m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="10m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence="medium",
            tags=["batch", "duration"],
        ))

        # ── Missed schedule ───────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Batch job missed schedule",
            description="Batch / cron job has not run within expected window — possible scheduler failure or service crash",
            severity="Major",
            signalflow=f"""
A = data("batch.job.last_success_timestamp", filter={f}).max(over="1h")
threshold = data("batch.job.last_success_timestamp", filter={f}).max(over="2h").timeshift("1h")
detect(when(A < threshold), lasting="5m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="low",
            tags=["batch", "schedule"],
        ))

        return detectors


class ObservabilityQualityTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Span export errors ────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] OTel span export errors elevated",
            description="OpenTelemetry span export failures — traces may be incomplete or missing from Splunk APM",
            severity="Warning",
            signalflow=f"""
A = data("otelcol_exporter_send_failed_spans", filter={f}).sum(over="5m")
detect(when(A > 100), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["otel", "observability", "traces"],
        ))

        # ── Metric reporting gap ──────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Service metrics stopped reporting",
            description="Service metrics have stopped reporting — OTel collector may be down or service crashed",
            severity="Critical",
            signalflow=f"""
A = data("service.request.count", filter={f}).sum(over="10m")
detect(when(A is None), lasting="10m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["observability", "staleness"],
        ))

        # ── Sampler drop rate ─────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] OTel trace sampler drop rate high",
            description="OTel trace sampler dropping too many spans — sampling rate may be too aggressive, reducing observability coverage",
            severity="Warning",
            signalflow=f"""
dropped = data("otelcol_processor_dropped_spans", filter={f}).sum(over="5m")
total = data("otelcol_receiver_accepted_spans", filter={f}).sum(over="5m")
drop_pct = dropped / total * 100
detect(when(drop_pct > 50), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="low",
            tags=["otel", "observability", "sampling"],
        ))

        return detectors
