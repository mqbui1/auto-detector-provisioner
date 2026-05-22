"""
RabbitMQ detector templates — queue depth, consumer count, unacked messages,
memory alarm, channel errors, publish/deliver rates.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class RabbitMQTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Queue depth high ──────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] RabbitMQ queue depth high",
            description="RabbitMQ queue message backlog elevated — consumers may be slow or stopped. Warn: >1000  Critical: >10000",
            severity="Major",
            signalflow=f"""
A = data("rabbitmq.queue.messages", {f}).max(over="5m")
detect(when(A > 10000), lasting="5m").publish("Critical")
detect(when(A > 1000) and when(A <= 10000), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["rabbitmq", "queue"],
        ))

        # ── Unacked messages high ─────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] RabbitMQ unacknowledged messages high",
            description="RabbitMQ unacked messages elevated — consumers processing slowly or stuck. Warn: >500  Critical: >5000",
            severity="Major",
            signalflow=f"""
A = data("rabbitmq.queue.messages.unacknowledged", {f}).max(over="5m")
detect(when(A > 5000), lasting="5m").publish("Critical")
detect(when(A > 500) and when(A <= 5000), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["rabbitmq", "queue", "consumers"],
        ))

        # ── Consumer count drop ───────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] RabbitMQ consumer count dropped",
            description="RabbitMQ consumer count dropped to zero — queue will accumulate with no processing",
            severity="Critical",
            signalflow=f"""
A = data("rabbitmq.queue.consumers", {f}).min(over="2m")
detect(when(A < 1), lasting="2m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["rabbitmq", "consumers"],
        ))

        # ── Memory alarm ──────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] RabbitMQ memory alarm triggered",
            description="RabbitMQ memory alarm active — broker will block publishers until memory drops below threshold",
            severity="Critical",
            signalflow=f"""
A = data("rabbitmq.node.mem_alarm", {f}).max(over="1m")
detect(when(A > 0), lasting="1m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["rabbitmq", "memory"],
        ))

        # ── Disk alarm ────────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] RabbitMQ disk free alarm triggered",
            description="RabbitMQ disk free space alarm active — broker will block all traffic",
            severity="Critical",
            signalflow=f"""
A = data("rabbitmq.node.disk_free_alarm", {f}).max(over="1m")
detect(when(A > 0), lasting="1m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["rabbitmq", "disk"],
        ))

        # ── Message publish rate drop ─────────────────────────────────────────
        if baseline and baseline.latency_mean_ms:
            # Use as proxy — no direct publish rate baseline, use dynamic anomaly
            detectors.append(DetectorTemplate(
                name=f"[{service}] RabbitMQ publish rate anomaly",
                description="RabbitMQ message publish rate deviating from baseline — possible producer issue",
                severity="Warning",
                signalflow=f"""
A = data("rabbitmq.channel.messages.published", {f}).rate(over="5m")
mean = data("rabbitmq.channel.messages.published", {f}).mean(over="1h")
detect(when(A < mean * 0.5), lasting="5m").publish("Warning")
""".strip(),
                threshold_type="dynamic",
                confidence="medium",
                tags=["rabbitmq", "publish_rate"],
            ))

        # ── Channel errors ────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] RabbitMQ channel error rate elevated",
            description="RabbitMQ channel errors elevated — possible message schema mismatch or routing issues",
            severity="Warning",
            signalflow=f"""
A = data("rabbitmq.channel.errors", {f}).sum(over="5m")
detect(when(A > 10), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["rabbitmq", "channel", "errors"],
        ))

        return detectors
