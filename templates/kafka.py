"""
Kafka detector templates — consumer lag, rebalance rate, producer errors.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class KafkaTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Consumer lag ──────────────────────────────────────────────────────
        # Best practice fixed thresholds — lag is universally bad regardless of baseline
        detectors.append(DetectorTemplate(
            name=f"[{service}] Kafka consumer lag high",
            description="Kafka consumer lag exceeding threshold — consumer falling behind producers. Warn: >1000  Critical: >10000",
            severity="Major",
            signalflow=f"""
A = data("kafka.consumer.fetch-manager-metrics.records-lag-max", {f}).max(over="5m")
detect(when(A > 10000), lasting="5m").publish("Critical")
detect(when(A > 1000) and when(A <= 10000), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="hybrid",
            confidence="high",
            tags=["kafka", "consumer", "lag"],
        ))

        # ── Consumer lag growth rate ──────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Kafka consumer lag growing",
            description="Kafka consumer lag is increasing — consumer may be stuck or undersized.",
            severity="Warning",
            signalflow=f"""
lag = data("kafka.consumer.fetch-manager-metrics.records-lag-max", {f}).mean(over="5m")
lag_delta = lag - lag.timeshift("10m")
detect(when(lag_delta > 500), lasting="10m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["kafka", "consumer", "lag"],
        ))

        # ── Consumer rebalance rate ───────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Kafka consumer rebalance rate high",
            description="Frequent consumer group rebalances — indicates unstable consumer group.",
            severity="Warning",
            signalflow=f"""
A = data("kafka.consumer.coordinator-metrics.rebalance-rate-avg", {f}).mean(over="5m")
detect(when(A > 0.1), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["kafka", "consumer", "rebalance"],
        ))

        # ── Producer error rate ───────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Kafka producer error rate",
            description="Kafka producer record error rate elevated — messages may be dropping.",
            severity="Major",
            signalflow=f"""
A = data("kafka.producer.producer-metrics.record-error-rate", {f}).mean(over="5m")
detect(when(A > 0.01), lasting="5m").publish("Warning")
detect(when(A > 0.05), lasting="5m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["kafka", "producer"],
        ))

        # ── DLQ depth ─────────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Kafka DLQ messages detected",
            description="Messages appearing in dead letter queue — indicates processing failures.",
            severity="Major",
            signalflow=f"""
A = data("kafka.consumer.fetch-manager-metrics.records-consumed-rate",
         {env_filter}filter("topic", "*dlq*") or filter("topic", "*dead*")).sum(over="5m")
detect(when(A > 0), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["kafka", "dlq"],
        ))

        return detectors
