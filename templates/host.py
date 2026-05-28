"""
Linux / Host metrics detector templates — CPU steal time, disk I/O saturation,
network packet loss, file descriptor exhaustion, memory pressure, swap usage.
Applies when kubernetes or aws_ec2 infra is detected.
"""
from __future__ import annotations
from .apm import DetectorTemplate
from typing import Any


class HostTemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── CPU utilization ───────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Host CPU utilization high",
            description="Host CPU utilization elevated — service may be CPU-bound. Warn: >80%  Critical: >95%",
            severity="Major",
            signalflow=f"""
A = data("cpu.utilization", filter={f}).mean(over="5m")
detect(when(A > 95), lasting="5m").publish("Critical")
detect(when(A > 80) and when(A <= 95), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["host", "cpu"],
        ))

        # ── CPU steal time ────────────────────────────────────────────────────
        # High steal = noisy neighbor on shared hypervisor
        detectors.append(DetectorTemplate(
            name=f"[{service}] Host CPU steal time high",
            description="CPU steal time high — noisy neighbor on shared hypervisor stealing CPU cycles. Warn: >10%  Critical: >25%",
            severity="Warning",
            signalflow=f"""
A = data("cpu.steal", filter={f}).mean(over="5m")
detect(when(A > 25), lasting="5m").publish("Critical")
detect(when(A > 10) and when(A <= 25), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["host", "cpu", "steal"],
        ))

        # ── Memory utilization ────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Host memory utilization high",
            description="Host memory utilization high — risk of OOM kills. Warn: >85%  Critical: >95%",
            severity="Major",
            signalflow=f"""
used = data("memory.utilization", filter={f}).mean(over="5m")
detect(when(used > 95), lasting="5m").publish("Critical")
detect(when(used > 85) and when(used <= 95), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["host", "memory"],
        ))

        # ── Disk I/O utilization ──────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Host disk I/O saturation",
            description="Host disk I/O utilization saturated — disk-bound workloads will experience latency. Warn: >80%  Critical: >95%",
            severity="Major",
            signalflow=f"""
A = data("disk.io.utilization", filter={f}).mean(over="5m")
detect(when(A > 95), lasting="5m").publish("Critical")
detect(when(A > 80) and when(A <= 95), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["host", "disk", "io"],
        ))

        # ── Disk space ────────────────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Host disk space low",
            description="Host disk free space critically low. Warn: <20%  Critical: <5%",
            severity="Major",
            signalflow=f"""
A = data("disk.summary_utilization", filter={f}).max(over="5m")
detect(when(A > 95), lasting="5m").publish("Critical")
detect(when(A > 80) and when(A <= 95), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="high",
            tags=["host", "disk", "space"],
        ))

        # ── Network packet loss ───────────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Host network packet loss elevated",
            description="Host network packet loss or errors elevated — network fabric issues affecting service communication",
            severity="Major",
            signalflow=f"""
errors = data("network.total_packets_dropped", filter={f}).mean(over="5m")
detect(when(errors > 100), lasting="5m").publish("Critical")
detect(when(errors > 10) and when(errors <= 100), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["host", "network"],
        ))

        # ── File descriptor exhaustion ────────────────────────────────────────
        detectors.append(DetectorTemplate(
            name=f"[{service}] Host file descriptors near limit",
            description="Host open file descriptors near system limit — service may fail to open new connections or files. Warn: >80%  Critical: >95%",
            severity="Major",
            signalflow=f"""
used = data("process.max_fds", filter={f}).mean(over="5m")
limit = data("system.max_fds", filter={f}).mean(over="5m")
fd_pct = used / limit * 100
detect(when(fd_pct > 95), lasting="5m").publish("Critical")
detect(when(fd_pct > 80) and when(fd_pct <= 95), lasting="5m").publish("Warning")
""".strip(),
            threshold_type="fixed",
            confidence="medium",
            tags=["host", "file_descriptors"],
        ))

        return detectors
