"""
Provisioner state — tracks what has been provisioned, when, and what the
baseline looked like at provision time. Enables idempotent reruns,
drift detection, and retune decisions.
"""
from __future__ import annotations

import fcntl
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

STATE_FILE = Path("data/provisioned_state.json")


@dataclass
class DetectorRecord:
    detector_id: str
    detector_name: str
    provisioned_at: float
    signalflow_hash: str          # hash of SignalFlow text — change = retune needed
    threshold_type: str           # fixed / dynamic / hybrid
    tags: list[str] = field(default_factory=list)


@dataclass
class ServiceState:
    service: str
    environment: str
    provisioned_at: float
    baseline_hash: str            # hash of baseline values — change triggers retune
    baseline_snapshot: dict = field(default_factory=dict)  # actual baseline values at provision time
    detector_records: list[DetectorRecord] = field(default_factory=list)
    last_retune_at: float = 0.0
    muted_until: float = 0.0      # epoch seconds; 0 = not muted
    archived: bool = False

    def detector_ids(self) -> list[str]:
        return [r.detector_id for r in self.detector_records if r.detector_id != "dry-run"]

    def is_muted(self) -> bool:
        return self.muted_until > time.time()

    def needs_retune(self, new_baseline_hash: str, retune_threshold_days: float = 7.0) -> bool:
        if self.baseline_hash != new_baseline_hash:
            return True
        days_since = (time.time() - self.last_retune_at) / 86400
        return days_since >= retune_threshold_days


class ProvisionerState:
    """
    Persistent state store for all provisioned services and detectors.
    Backed by data/provisioned_state.json.
    """

    def __init__(self, path: Path = STATE_FILE):
        self.path = path
        self._services: dict[str, ServiceState] = {}
        self._load()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text())
            for key, sdata in raw.items():
                records = [
                    DetectorRecord(**r)
                    for r in (sdata.get("detector_records") or [])
                ]
                self._services[key] = ServiceState(
                    service=sdata["service"],
                    environment=sdata["environment"],
                    provisioned_at=sdata.get("provisioned_at", 0),
                    baseline_hash=sdata.get("baseline_hash", ""),
                    baseline_snapshot=sdata.get("baseline_snapshot", {}),
                    detector_records=records,
                    last_retune_at=sdata.get("last_retune_at", 0),
                    muted_until=sdata.get("muted_until", 0),
                    archived=sdata.get("archived", False),
                )
            logger.debug("State: loaded %d service records from %s", len(self._services), self.path)
        except Exception as e:
            logger.warning("State: failed to load %s: %s", self.path, e)

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        raw = {}
        for key, s in self._services.items():
            raw[key] = {
                "service": s.service,
                "environment": s.environment,
                "provisioned_at": s.provisioned_at,
                "baseline_hash": s.baseline_hash,
                "baseline_snapshot": s.baseline_snapshot,
                "last_retune_at": s.last_retune_at,
                "muted_until": s.muted_until,
                "archived": s.archived,
                "detector_records": [
                    {
                        "detector_id": r.detector_id,
                        "detector_name": r.detector_name,
                        "provisioned_at": r.provisioned_at,
                        "signalflow_hash": r.signalflow_hash,
                        "threshold_type": r.threshold_type,
                        "tags": r.tags,
                    }
                    for r in s.detector_records
                ],
            }
        # Write via temp file + atomic rename to prevent partial reads,
        # and use an exclusive lock to prevent concurrent write races
        tmp = self.path.with_suffix(".tmp")
        lock = self.path.with_suffix(".lock")
        lock.parent.mkdir(parents=True, exist_ok=True)
        with open(lock, "w") as lf:
            try:
                fcntl.flock(lf, fcntl.LOCK_EX)
                tmp.write_text(json.dumps(raw, indent=2))
                tmp.replace(self.path)
            finally:
                fcntl.flock(lf, fcntl.LOCK_UN)
        logger.debug("State: saved %d service records to %s", len(self._services), self.path)

    # ── Accessors ─────────────────────────────────────────────────────────────

    def _key(self, service: str, environment: str) -> str:
        return f"{environment}/{service}"

    def get(self, service: str, environment: str) -> ServiceState | None:
        return self._services.get(self._key(service, environment))

    def all_services(self) -> list[ServiceState]:
        return list(self._services.values())

    def is_provisioned(self, service: str, environment: str) -> bool:
        s = self.get(service, environment)
        return s is not None and not s.archived

    # ── Mutations ─────────────────────────────────────────────────────────────

    def record_provision(
        self,
        service: str,
        environment: str,
        baseline_hash: str,
        detector_records: list[DetectorRecord],
        baseline_snapshot: dict | None = None,
    ) -> None:
        key = self._key(service, environment)
        now = time.time()
        self._services[key] = ServiceState(
            service=service,
            environment=environment,
            provisioned_at=now,
            baseline_hash=baseline_hash,
            baseline_snapshot=baseline_snapshot or {},
            detector_records=detector_records,
            last_retune_at=now,
        )
        self.save()

    def record_retune(
        self,
        service: str,
        environment: str,
        new_baseline_hash: str,
        updated_records: list[DetectorRecord],
        baseline_snapshot: dict | None = None,
    ) -> None:
        key = self._key(service, environment)
        s = self._services.get(key)
        if s:
            s.baseline_hash = new_baseline_hash
            s.baseline_snapshot = baseline_snapshot or s.baseline_snapshot
            s.detector_records = updated_records
            s.last_retune_at = time.time()
            self.save()

    def mute(self, service: str, environment: str, duration_minutes: int) -> None:
        key = self._key(service, environment)
        s = self._services.get(key)
        if s:
            s.muted_until = time.time() + duration_minutes * 60
            self.save()
            logger.info("State: muted %s/%s for %dm", environment, service, duration_minutes)

    def unmute(self, service: str, environment: str) -> None:
        key = self._key(service, environment)
        s = self._services.get(key)
        if s:
            s.muted_until = 0.0
            self.save()
            logger.info("State: unmuted %s/%s", environment, service)

    def archive(self, service: str, environment: str) -> None:
        key = self._key(service, environment)
        s = self._services.get(key)
        if s:
            s.archived = True
            self.save()
            logger.info("State: archived %s/%s", environment, service)
