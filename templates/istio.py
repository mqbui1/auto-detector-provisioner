"""
Istio / Envoy sidecar detector templates — sidecar error rate,
circuit breaker open, retry budget exhausted, upstream connection failures,
request throughput anomaly, mTLS failures.
Uses Istio standard metrics (istio_* / envoy_*).
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class IstioTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Sidecar request error rate ────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Istio sidecar request error rate high",
            description="Istio sidecar (Envoy) request error rate elevated — proxy-level failures. Warn: >1%  Critical: >5%",
            severity="Major",
            signalflow=f"""
total = data("istio_requests_total", filter={f}).sum(over="2m")
errors = data("istio_requests_total", filter={f} and filter("response_code", "5*")).sum(over="2m")
error_pct = errors / total * 100
detect(when(error_pct > 5), lasting="2m").publish("Critical")
detect(when(error_pct > 1) and when(error_pct <= 5), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["istio", "envoy", "errors"],
        ))

        # ── Circuit breaker open ──────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Istio circuit breaker open",
            description="Istio Envoy circuit breaker open — upstream ejections occurring. Traffic is being blocked to a failing host.",
            severity="Critical",
            signalflow=f"""
A = data("envoy_cluster_outlier_detection_ejections_active", filter={f}).max(over="2m")
detect(when(A > 0), lasting="2m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["istio", "circuit_breaker"],
        ))

        # ── Upstream connection failures ──────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Istio upstream connection failures elevated",
            description="Istio Envoy upstream connection failures — service mesh connectivity issues between services",
            severity="Major",
            signalflow=f"""
A = data("envoy_cluster_upstream_cx_connect_fail", filter={f}).sum(over="5m")
detect(when(A > 10), lasting="5m").publish("Critical")
detect(when(A > 1) and when(A <= 10), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["istio", "envoy", "connections"],
        ))

        # ── Request latency (p99) ─────────────────────────────────────────────
        if baseline and baseline.latency_p99_ms:
            w_sigma, c_sigma = baseline.sigma_multipliers()
            warn_t = round(baseline.latency_mean_ms + w_sigma * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + c_sigma * baseline.latency_stddev_ms, 1)
            desc = f"Istio sidecar request latency anomaly. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms"
            threshold_type = "dynamic"
        else:
            warn_t, anomaly_t = 500, 1000
            desc = "Istio sidecar request latency high. Warn: >500ms  Critical: >1000ms"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Istio sidecar request latency high",
            description=desc,
            severity="Major",
            signalflow=f"""
A = data("istio_request_duration_milliseconds", filter={f}).percentile(pct=99, over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence="high",
            tags=["istio", "latency"],
        ))

        # ── Retry budget exhausted ────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Istio retry budget exhausted",
            description="Istio retry budget exhausted — too many retries in flight, upstream is saturated",
            severity="Major",
            signalflow=f"""
A = data("envoy_cluster_upstream_rq_retry_overflow", filter={f}).sum(over="5m")
detect(when(A > 0), lasting="2m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["istio", "retries"],
        ))

        # ── mTLS handshake failures ───────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Istio mTLS handshake failures",
            description="Istio mTLS handshake failures detected — certificate rotation issue or policy misconfiguration",
            severity="Critical",
            signalflow=f"""
A = data("envoy_listener_ssl_handshake_error", filter={f}).sum(over="5m")
detect(when(A > 5), lasting="5m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["istio", "mtls", "security"],
        ))

        # ── Pending requests high ─────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Istio upstream pending requests high",
            description="Istio Envoy upstream pending request queue elevated — upstream cluster overloaded. Warn: >100  Critical: >500",
            severity="Warning",
            signalflow=f"""
A = data("envoy_cluster_upstream_rq_pending_active", filter={f}).max(over="2m")
detect(when(A > 500), lasting="2m").publish("Critical")
detect(when(A > 100) and when(A <= 500), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["istio", "envoy", "pending"],
        ))

        return detectors
