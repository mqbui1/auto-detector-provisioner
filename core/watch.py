"""
Watch daemon — continuous provisioning mode.

Runs in a loop:
  1. Discover new services → provision detectors automatically
  2. Check existing services for baseline drift → retune
  3. Check for stale services → archive (dry-run by default)
  4. Sleep until next poll

Designed to run as a long-lived process (k8s pod, systemd service, etc.)
SIGTERM / KeyboardInterrupt triggers graceful shutdown.
"""
from __future__ import annotations

import logging
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from .discovery import discover_services
from .baseline_learner import learn_baseline, load_baseline
from .detector_generator import generate_detectors
from .detector_deployer import deploy_detectors, DeployResult
from .retune import retune_service, baseline_hash, format_retune_summary, signalflow_hash
from .archive import archive_stale_services, archive_service, format_archive_summary
from .state import ProvisionerState, DetectorRecord, STATE_FILE

logger = logging.getLogger(__name__)


@dataclass
class WatchConfig:
    realm: str
    token: str
    environment: str | None
    poll_interval_minutes: int = 60
    retune_interval_days: float = 7.0
    stale_threshold_days: float = 7.0
    baseline_window_hours: int = 24
    baseline_dir: Path = Path("data/baselines")
    state_path: Path = STATE_FILE
    auto_archive: bool = False       # archive stale services automatically
    dry_run: bool = True             # safe default — never deploy without explicit opt-in
    include_low_confidence: bool = False


class WatchDaemon:

    def __init__(self, config: WatchConfig):
        self.config = config
        self.state = ProvisionerState(config.state_path)
        self._running = True
        self._cycle = 0

        # Graceful shutdown on SIGTERM
        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signum, frame):
        logger.info("Watch: received signal %d — shutting down gracefully", signum)
        self._running = False

    def run(self) -> None:
        cfg = self.config
        mode = "DRY RUN" if cfg.dry_run else "AUTO-DEPLOY"
        logger.info("Watch: starting [%s] realm=%s env=%s poll=%dm",
                    mode, cfg.realm, cfg.environment or "all", cfg.poll_interval_minutes)

        while self._running:
            self._cycle += 1
            cycle_start = time.time()

            try:
                self._run_cycle()
            except Exception as e:
                logger.error("Watch: cycle %d failed: %s", self._cycle, e)

            elapsed = time.time() - cycle_start
            sleep_secs = max(0, cfg.poll_interval_minutes * 60 - elapsed)

            if self._running:
                logger.info(
                    "Watch: cycle %d complete (%.1fs) — sleeping %dm until next poll",
                    self._cycle, elapsed, sleep_secs / 60,
                )
                self._interruptible_sleep(sleep_secs)

        logger.info("Watch: stopped after %d cycles", self._cycle)

    def _run_cycle(self) -> None:
        cfg = self.config
        logger.info("Watch: cycle %d — discovering services (env=%s)",
                    self._cycle, cfg.environment or "all")

        # ── Step 1: Discover all current services ─────────────────────────────
        profiles = discover_services(
            realm=cfg.realm,
            token=cfg.token,
            environment=cfg.environment,
        )

        new_services = [
            p for p in profiles
            if not self.state.is_provisioned(p.service, p.environment)
        ]
        existing_services = [
            p for p in profiles
            if self.state.is_provisioned(p.service, p.environment)
        ]

        logger.info(
            "Watch: %d total services — %d new, %d existing",
            len(profiles), len(new_services), len(existing_services),
        )

        # Mark all discovered services as seen (for accurate stale detection)
        for p in profiles:
            self.state.touch_seen(p.service, p.environment)
        self.state.save()

        # ── Step 2: Provision new services ────────────────────────────────────
        for profile in new_services:
            if not self._running:
                break
            self._provision_new(profile)

        # ── Step 3: Retune existing services ──────────────────────────────────
        for profile in existing_services:
            if not self._running:
                break
            svc_state = self.state.get(profile.service, profile.environment)
            if svc_state and svc_state.is_muted():
                logger.debug("Watch: %s/%s is muted — skipping retune",
                             profile.environment, profile.service)
                continue
            self._retune_if_needed(profile)

        # ── Step 4: Check for stale services ──────────────────────────────────
        active_keys = {
            f"{p.environment}/{p.service}" for p in profiles
        }
        self._check_stale(active_keys)

    def _provision_new(self, profile) -> None:
        cfg = self.config
        logger.info("Watch: provisioning new service %s/%s", profile.environment, profile.service)

        # Learn baseline
        baseline = None
        baseline_path = cfg.baseline_dir / f"{profile.environment}__{profile.service}.json"
        baseline = load_baseline(baseline_path) or learn_baseline(
            realm=cfg.realm,
            token=cfg.token,
            service=profile.service,
            environment=profile.environment,
            window_hours=cfg.baseline_window_hours,
            output_dir=cfg.baseline_dir,
        )
        if not baseline.is_reliable():
            baseline = None

        # Generate detectors
        detectors = generate_detectors(
            profile=profile,
            baseline=baseline,
            include_low_confidence=cfg.include_low_confidence,
            realm=cfg.realm,
            token=cfg.token,
        )

        # Deploy
        results = deploy_detectors(
            realm=cfg.realm,
            token=cfg.token,
            service=profile.service,
            environment=profile.environment,
            detectors=detectors,
            dry_run=cfg.dry_run,
        )

        # Record in state
        b_hash = baseline_hash(baseline) if baseline else "no-baseline"
        records = [
            DetectorRecord(
                detector_id=r.detector_id or "dry-run",
                detector_name=r.detector_name,
                provisioned_at=time.time(),
                signalflow_hash=signalflow_hash(
                    next((d.signalflow for d in detectors if d.name == r.detector_name), "")
                ),
                threshold_type=next(
                    (d.threshold_type for d in detectors if d.name == r.detector_name), "fixed"
                ),
                tags=next((d.tags for d in detectors if d.name == r.detector_name), []),
            )
            for r in results if r.success
        ]
        b_snapshot = {
            "latency_mean_ms": baseline.latency_mean_ms if baseline else None,
            "latency_stddev_ms": baseline.latency_stddev_ms if baseline else None,
            "error_rate_pct": baseline.error_rate_pct if baseline else None,
            "error_rate_stddev_pct": baseline.error_rate_stddev_pct if baseline else None,
            "sample_count": baseline.sample_count if baseline else 0,
        }
        self.state.record_provision(
            service=profile.service,
            environment=profile.environment,
            baseline_hash=b_hash,
            detector_records=records,
            baseline_snapshot=b_snapshot,
        )

        succeeded = sum(1 for r in results if r.success)
        logger.info(
            "Watch: provisioned %s/%s — %d/%d detectors %s",
            profile.environment, profile.service,
            succeeded, len(results),
            "would be created" if cfg.dry_run else "created",
        )

    def _retune_if_needed(self, profile) -> None:
        cfg = self.config
        svc_state = self.state.get(profile.service, profile.environment)
        if not svc_state:
            return

        # Use cached baseline if fresh; only call API if cache is stale/missing
        baseline_path = cfg.baseline_dir / f"{profile.environment}__{profile.service}.json"
        baseline = load_baseline(baseline_path)
        if not baseline:
            baseline = learn_baseline(
                realm=cfg.realm,
                token=cfg.token,
                service=profile.service,
                environment=profile.environment,
                window_hours=cfg.baseline_window_hours,
                output_dir=cfg.baseline_dir,
            )

        if not baseline.is_reliable():
            logger.debug("Watch: %s/%s baseline unreliable — skipping retune",
                         profile.environment, profile.service)
            return

        new_hash = baseline_hash(baseline)
        if not svc_state.needs_retune(new_hash, cfg.retune_interval_days):
            logger.debug("Watch: %s/%s no retune needed", profile.environment, profile.service)
            return

        results = retune_service(
            realm=cfg.realm,
            token=cfg.token,
            service=profile.service,
            environment=profile.environment,
            new_baseline=baseline,
            state=self.state,
            dry_run=cfg.dry_run,
            retune_interval_days=cfg.retune_interval_days,
        )

        updated = sum(1 for r in results if r.action == "updated")
        if updated:
            logger.info(
                "Watch: retuned %s/%s — %d detectors updated",
                profile.environment, profile.service, updated,
            )

    def _check_stale(self, active_keys: set[str]) -> None:
        cfg = self.config

        for svc_state in self.state.all_services():
            if svc_state.archived:
                continue
            key = f"{svc_state.environment}/{svc_state.service}"
            if key not in active_keys:
                # Use last_seen_at if available, fall back to provisioned_at for legacy records
                last_seen = svc_state.last_seen_at or svc_state.provisioned_at
                days_absent = (time.time() - last_seen) / 86400
                if days_absent >= cfg.stale_threshold_days:
                    logger.warning(
                        "Watch: %s/%s not seen in discovery for %.0f days — "
                        "consider archiving (run with --archive-stale)",
                        svc_state.environment, svc_state.service,
                        days_absent,
                    )
                    if cfg.auto_archive:
                        result = archive_service(
                            realm=cfg.realm,
                            token=cfg.token,
                            service=svc_state.service,
                            environment=svc_state.environment,
                            state=self.state,
                            dry_run=cfg.dry_run,
                            reason=f"not seen in discovery for {days_absent:.0f} days",
                        )
                        logger.info("Watch: archive result for %s/%s: %s",
                                    svc_state.environment, svc_state.service, result.action)

    def _interruptible_sleep(self, seconds: float) -> None:
        """Sleep in small increments so SIGTERM is handled promptly."""
        end = time.time() + seconds
        while self._running and time.time() < end:
            time.sleep(min(5.0, end - time.time()))
