"""
AWS infrastructure detector templates — EC2, RDS, Lambda, ECS, SQS.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class AWSTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Lambda error rate ─────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Lambda error rate high",
            description="AWS Lambda error rate elevated. Warn: >1%  Critical: >5%",
            severity="Major",
            signalflow=f"""
errors = data("aws.lambda.errors", filter={f}).sum(over="5m")
invocations = data("aws.lambda.invocations", filter={f}).sum(over="5m")
error_rate = errors / invocations * 100
detect(when(error_rate > 5), lasting="5m").publish("Critical")
detect(when(error_rate > 1) and when(error_rate <= 5), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["aws", "lambda", "error_rate"],
        ))

        # ── Lambda throttle rate ──────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Lambda throttling detected",
            description="Lambda invocations being throttled — concurrent execution limit reached.",
            severity="Major",
            signalflow=f"""
A = data("aws.lambda.throttles", filter={f}).sum(over="5m")
detect(when(A > 0), lasting="5m").publish("Warning")
detect(when(A > 10), lasting="5m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["aws", "lambda", "throttle"],
        ))

        # ── Lambda cold start rate ────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Lambda cold start rate high",
            description="Lambda cold start rate elevated — consider provisioned concurrency.",
            severity="Warning",
            signalflow=f"""
A = data("aws.lambda.init_duration", filter={f}).count(over="5m")
B = data("aws.lambda.invocations", filter={f}).sum(over="5m")
cold_start_rate = A / B * 100
detect(when(cold_start_rate > 20), lasting="10m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["aws", "lambda", "cold_start"],
        ))

        # ── RDS connection saturation ─────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] RDS connection count high",
            description="RDS database connections near instance limit. Warn: >80%  Critical: >95%",
            severity="Major",
            signalflow=f"""
A = data("aws.rds.database_connections", filter={f}).mean(over="5m")
detect(when(A > 950), lasting="5m").publish("Critical")
detect(when(A > 800) and when(A <= 950), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["aws", "rds", "connections"],
        ))

        # ── RDS replica lag ───────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] RDS replica lag high",
            description="RDS read replica lag elevated — reads from replica may return stale data. Warn: >30s  Critical: >120s",
            severity="Major",
            signalflow=f"""
A = data("aws.rds.replica_lag", filter={f}).mean(over="5m")
detect(when(A > 120), lasting="5m").publish("Critical")
detect(when(A > 30) and when(A <= 120), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["aws", "rds", "replica"],
        ))

        # ── SQS approximate age of oldest message ─────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] SQS message age high",
            description="SQS messages not being consumed in time — consumer may be falling behind. Warn: >300s  Critical: >900s",
            severity="Major",
            signalflow=f"""
A = data("aws.sqs.approximate_age_of_oldest_message", filter={f}).mean(over="5m")
detect(when(A > 900), lasting="5m").publish("Critical")
detect(when(A > 300) and when(A <= 900), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["aws", "sqs", "lag"],
        ))

        # ── SQS DLQ depth ─────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] SQS dead letter queue has messages",
            description="Messages in SQS DLQ — processing failures occurring.",
            severity="Major",
            signalflow=f"""
A = data("aws.sqs.approximate_number_of_messages_visible",
         {env_filter}filter("QueueName", "*dlq*") or filter("QueueName", "*dead*")).sum(over="5m")
detect(when(A > 0), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["aws", "sqs", "dlq"],
        ))

        # ── ECS running vs desired ────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] ECS running tasks below desired",
            description="ECS service has fewer running tasks than desired count.",
            severity="Major",
            signalflow=f"""
desired = data("aws.ecs.service.desired_count", filter={f}).mean(over="5m")
running = data("aws.ecs.service.running_count", filter={f}).mean(over="5m")
detect(when(running < desired), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["aws", "ecs", "availability"],
        ))

        return detectors
