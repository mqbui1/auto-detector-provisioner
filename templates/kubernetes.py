"""
Kubernetes detector templates — pod restarts, OOMKilled, CPU throttling,
HPA, PVC, pending pods.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class KubernetesTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── Pod restart rate ──────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Pod restart rate high",
            description="Pod restart rate abnormally high — possible crash loop. Warn: >2/5min  Critical: >5/5min",
            severity="Major",
            signalflow=f"""
A = data("k8s.pod.phase", {f}, filter("phase", "Running")).count()
restarts = data("k8s.container.restarts", {f}).sum(over="5m")
detect(when(restarts > 5), lasting="5m").publish("Critical")
detect(when(restarts > 2) and when(restarts <= 5), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["kubernetes", "availability"],
        ))

        # ── OOMKilled ─────────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] OOMKilled detected",
            description="Container was OOMKilled — memory limit too low or memory leak.",
            severity="Critical",
            signalflow=f"""
A = data("k8s.container.restarts", {f}, filter("reason", "OOMKilled")).sum(over="10m")
detect(when(A > 0), lasting="1m").publish("Critical")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["kubernetes", "memory", "oomkilled"],
        ))

        # ── CPU throttling ────────────────────────────────────────────────────
        # Best practice: warn >25% throttled, critical >50%
        detectors.append(DetectorTemplate(
            name=f"[{service}] CPU throttling high",
            description="Container CPU being throttled — CPU limit may be too low. Warn: >25%  Critical: >50%",
            severity="Warning",
            signalflow=f"""
throttled = data("container.cpu.throttling_data.throttled_time", {f}).sum(over="5m")
total = data("container.cpu.throttling_data.total_elapsed_time", {f}).sum(over="5m")
throttle_pct = throttled / total * 100
detect(when(throttle_pct > 50), lasting="5m").publish("Critical")
detect(when(throttle_pct > 25) and when(throttle_pct <= 50), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["kubernetes", "cpu"],
        ))

        # ── HPA at max replicas ───────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] HPA at maximum replicas",
            description="HPA has reached max replicas — service may be unable to scale further under load.",
            severity="Warning",
            signalflow=f"""
current = data("k8s.hpa.current_replicas", {f}).mean(over="5m")
max_r = data("k8s.hpa.max_replicas", {f}).mean(over="5m")
detect(when(current >= max_r), lasting="10m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["kubernetes", "scaling", "hpa"],
        ))

        # ── Pending pods ──────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Pods stuck in Pending state",
            description="Pods stuck in Pending — possible resource quota exhaustion or node pressure.",
            severity="Major",
            signalflow=f"""
A = data("k8s.pod.phase", {f}, filter("phase", "Pending")).count()
detect(when(A > 0), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["kubernetes", "availability"],
        ))

        # ── Desired vs running replicas ───────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Running replicas below desired",
            description="Fewer running pods than desired — deployment may be degraded.",
            severity="Major",
            signalflow=f"""
desired = data("k8s.deployment.desired", {f}).mean(over="5m")
available = data("k8s.deployment.available", {f}).mean(over="5m")
detect(when(available < desired), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["kubernetes", "availability"],
        ))

        return detectors
