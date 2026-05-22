"""
gRPC detector templates — per-RPC error rate, latency by method,
deadline exceeded rate, stream cancellations, connection pool.
Uses OpenTelemetry RPC semantic conventions (rpc.* metrics).
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class GRPCTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── RPC error rate ────────────────────────────────────────────────────
        # grpc status codes: OK=0, any non-zero is an error
        detectors.append(DetectorTemplate(
            name=f"[{service}] gRPC error rate high",
            description="gRPC RPC error rate elevated (non-OK status codes). Warn: >1%  Critical: >5%",
            severity="Major",
            signalflow=f"""
total = data("rpc.server.requests_per_rpc", {f}).sum(over="2m")
errors = data("rpc.server.requests_per_rpc", {f}, filter=filter("rpc.grpc.status_code", "!0")).sum(over="2m")
error_pct = errors / total * 100
detect(when(error_pct > 5), lasting="2m").publish("Critical")
detect(when(error_pct > 1) and when(error_pct <= 5), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["grpc", "rpc", "errors"],
        ))

        # ── RPC latency (server-side) ─────────────────────────────────────────
        if baseline and baseline.latency_p99_ms:
            warn_t = round(baseline.latency_mean_ms + 2.0 * baseline.latency_stddev_ms, 1)
            anomaly_t = round(baseline.latency_mean_ms + 3.0 * baseline.latency_stddev_ms, 1)
            desc = f"gRPC server latency anomaly. Warn: >{warn_t}ms  Anomaly: >{anomaly_t}ms"
            threshold_type = "dynamic"
        else:
            warn_t, anomaly_t = 200, 500
            desc = "gRPC server RPC latency high. Warn: >200ms  Critical: >500ms"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] gRPC server RPC latency high",
            description=desc,
            severity="Major",
            signalflow=f"""
A = data("rpc.server.duration", {f}).percentile(pct=99, over="5m")
detect(when(A > {anomaly_t}), lasting="5m").publish("Anomaly")
detect(when(A > {warn_t}) and when(A <= {anomaly_t}), lasting="5m").publish("Warning")
""".strip(),
            threshold_type=threshold_type,
            confidence="high",
            tags=["grpc", "rpc", "latency"],
        ))

        # ── Deadline exceeded rate ────────────────────────────────────────────
        # DEADLINE_EXCEEDED (status code 4) is a leading indicator of cascading failure
        detectors.append(DetectorTemplate(
            name=f"[{service}] gRPC deadline exceeded rate elevated",
            description="gRPC DEADLINE_EXCEEDED errors elevated — downstream services may be slow or a timeout is too tight",
            severity="Major",
            signalflow=f"""
total = data("rpc.server.requests_per_rpc", {f}).sum(over="5m")
deadlines = data("rpc.server.requests_per_rpc", {f}, filter=filter("rpc.grpc.status_code", "4")).sum(over="5m")
deadline_pct = deadlines / total * 100
detect(when(deadline_pct > 5), lasting="5m").publish("Critical")
detect(when(deadline_pct > 1) and when(deadline_pct <= 5), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["grpc", "deadline", "errors"],
        ))

        # ── Unavailable / connection errors ───────────────────────────────────
        # UNAVAILABLE (status code 14) = service unreachable / connection reset
        detectors.append(DetectorTemplate(
            name=f"[{service}] gRPC UNAVAILABLE errors detected",
            description="gRPC UNAVAILABLE errors (status 14) — service unreachable or connection being reset",
            severity="Critical",
            signalflow=f"""
A = data("rpc.server.requests_per_rpc", {f}, filter=filter("rpc.grpc.status_code", "14")).sum(over="2m")
detect(when(A > 5), lasting="2m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["grpc", "connection", "errors"],
        ))

        # ── Stream cancellation rate ──────────────────────────────────────────
        # CANCELLED (status code 1) — clients cancelling streams can indicate slow server
        detectors.append(DetectorTemplate(
            name=f"[{service}] gRPC client cancellation rate elevated",
            description="gRPC client-initiated stream cancellations elevated — clients timing out or giving up on slow responses",
            severity="Warning",
            signalflow=f"""
total = data("rpc.server.requests_per_rpc", {f}).sum(over="5m")
cancelled = data("rpc.server.requests_per_rpc", {f}, filter=filter("rpc.grpc.status_code", "1")).sum(over="5m")
cancel_pct = cancelled / total * 100
detect(when(cancel_pct > 10), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["grpc", "streaming", "cancellation"],
        ))

        # ── Client-side error rate ────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] gRPC client RPC error rate high",
            description="gRPC outbound (client-side) RPC error rate elevated — downstream dependency issues",
            severity="Major",
            signalflow=f"""
total = data("rpc.client.requests_per_rpc", {f}).sum(over="2m")
errors = data("rpc.client.requests_per_rpc", {f}, filter=filter("rpc.grpc.status_code", "!0")).sum(over="2m")
error_pct = errors / total * 100
detect(when(error_pct > 5), lasting="2m").publish("Critical")
detect(when(error_pct > 1) and when(error_pct <= 5), lasting="2m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["grpc", "rpc", "client", "errors"],
        ))

        return detectors
