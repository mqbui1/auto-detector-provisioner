"""
Node.js detector templates — heap, event loop lag, libuv thread pool.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class NodeJSTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        # OTel Node.js runtime metrics carry service.name + deployment.environment,
        # not sf_service + sf_environment. Use OTel dimensions for runtime detectors.
        env_filter_rt = f'filter("deployment.environment", "{environment}") and ' if environment else ""
        svc_filter_rt = f'filter("service.name", "{service}")'
        f_rt = f"{env_filter_rt}{svc_filter_rt}"

        detectors = []

        # nodejs.eventloop.delay.mean / .p99 — stable metric from @opentelemetry/instrumentation-runtime-node
        detectors.append(DetectorTemplate(
            name=f"[{service}] Node.js event loop lag high",
            description="Node.js event loop lag elevated — I/O blocking or CPU-intensive work on main thread. Warn: >100ms  Critical: >500ms",
            severity="Major",
            signalflow=f"""
A = data("nodejs.eventloop.delay.mean", filter={f_rt}).mean(over="5m")
detect(when(A > 500), lasting="5m").publish("Critical")
detect(when(A > 100) and when(A <= 500), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["nodejs", "event_loop"],
            rationale=(
                "Node.js is single-threaded. When the event loop is blocked by CPU-heavy work, "
                "large JSON parsing, or synchronous I/O, all in-flight requests queue behind it. "
                "Event loop lag directly measures how long callbacks wait to execute after being "
                "scheduled — it is the definitive signal for main-thread saturation. >100ms is "
                "perceptible to users; >500ms means the service is effectively stalled. "
                "Metric: nodejs.eventloop.delay.mean from "
                "@opentelemetry/instrumentation-runtime-node. "
                "Source: Node.js Performance Team best practices; Netflix, Datadog Node.js SRE guides."
            ),
        ))

        # nodejs.eventloop.utilization — fraction of time loop is active (0-1)
        detectors.append(DetectorTemplate(
            name=f"[{service}] Node.js event loop utilization high",
            description="Node.js event loop utilization near saturation — main thread overloaded. Warn: >80%  Critical: >95%",
            severity="Major",
            signalflow=f"""
A = data("nodejs.eventloop.utilization", filter={f_rt}).mean(over="5m") * 100
detect(when(A > 95), lasting="5m").publish("Critical")
detect(when(A > 80) and when(A <= 95), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["nodejs", "event_loop"],
            rationale=(
                "Event Loop Utilization (ELU) is the fraction of time the loop is active vs idle "
                "(0.0–1.0), measured via libuv's uv_metrics_idle_time(). It is more reliable than "
                "lag for detecting sustained load because lag spikes can be brief and miss a 5m "
                "window average. >80% means the loop has almost no idle time — saturation is "
                "imminent. >95% is effective saturation; new requests will experience queuing delay. "
                "Metric: nodejs.eventloop.utilization from @opentelemetry/instrumentation-runtime-node "
                "(introduced Node.js 14.10 / libuv 1.39). "
                "Source: Node.js diagnostics working group; clinic.js / 0x profiling methodology."
            ),
        ))

        return detectors
