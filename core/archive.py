"""
Archive manager — detects decommissioned services and cleans up their detectors.

A service is considered decommissioned if:
  1. It has not emitted spans in N days (configurable, default 7)
  2. It no longer appears in the APM service catalog
  3. It was explicitly archived via --archive flag

On archive: detectors are deleted via DELETE /v2/detector/{id},
muting rules are removed, and state is marked archived.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from .state import ProvisionerState, ServiceState
from .mute import unmute_service

logger = logging.getLogger(__name__)

DEFAULT_STALE_DAYS = 7.0


@dataclass
class ArchiveResult:
    service: str
    environment: str
    action: str          # "archived" | "skipped" | "failed"
    detectors_deleted: int = 0
    reason: str = ""


def _api_delete(api_base: str, token: str, detector_id: str) -> None:
    url = f"{api_base}/v2/detector/{detector_id}"
    req = urllib.request.Request(url, headers={"X-SF-Token": token}, method="DELETE")
    try:
        with urllib.request.urlopen(req, timeout=30):
            pass
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return  # already deleted — fine
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:300].decode()}")


def _service_still_active(
    app_base: str,
    token: str,
    service: str,
    environment: str,
) -> bool:
    """
    Confirm a service is still active by checking the live APM catalog.
    Returns True if the service appears; used as a final guard before archiving.
    """
    body = {
        "operationName": "GetServices",
        "variables": {"environmentFilter": environment},
        "query": (
            "query GetServices($environmentFilter: String) {"
            " serviceNames(environmentName: $environmentFilter) }"
        ),
    }
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        f"{app_base}/v2/apm/graphql?op=GetServices", data=data,
        headers={"X-SF-Token": token, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read().decode())
            names = ((result.get("data") or {}).get("serviceNames") or [])
            return service in names
    except Exception as e:
        logger.warning("Archive: could not check service activity for %s: %s", service, e)
        return True  # assume active on error — safer than false positive archive


def check_stale_services(
    realm: str,
    token: str,
    state: ProvisionerState,
    stale_days: float = DEFAULT_STALE_DAYS,
) -> list[ServiceState]:
    """
    Return provisioned services not seen in discovery for stale_days.
    Uses last_seen_at from state (updated every watch cycle) for the time check,
    then confirms absence with a live APM catalog query to avoid false positives.
    """
    app_base = f"https://app.{realm}.signalfx.com"
    stale = []

    for svc_state in state.all_services():
        if svc_state.archived:
            continue
        last_seen = svc_state.last_seen_at or svc_state.provisioned_at
        days_absent = (time.time() - last_seen) / 86400
        if days_absent < stale_days:
            continue
        # Time threshold crossed — confirm with live APM catalog before flagging
        if not _service_still_active(app_base, token, svc_state.service, svc_state.environment):
            logger.info(
                "Archive: %s/%s absent %.0f days (threshold=%.0f) — candidate for archival",
                svc_state.environment, svc_state.service, days_absent, stale_days,
            )
            stale.append(svc_state)

    return stale


def archive_service(
    realm: str,
    token: str,
    service: str,
    environment: str,
    state: ProvisionerState,
    dry_run: bool = True,
    reason: str = "service decommissioned",
) -> ArchiveResult:
    """
    Delete all detectors for a service and mark it archived in state.
    """
    api_base = f"https://api.{realm}.signalfx.com"

    svc_state = state.get(service, environment)
    if not svc_state:
        return ArchiveResult(
            service=service, environment=environment,
            action="skipped", reason="not in provisioned state",
        )

    if svc_state.archived:
        return ArchiveResult(
            service=service, environment=environment,
            action="skipped", reason="already archived",
        )

    detector_ids = svc_state.detector_ids()

    if dry_run:
        logger.info(
            "[DRY RUN] Would archive %s/%s — delete %d detectors",
            environment, service, len(detector_ids),
        )
        return ArchiveResult(
            service=service, environment=environment,
            action="archived",
            detectors_deleted=len(detector_ids),
            reason=f"dry-run — would delete {len(detector_ids)} detectors: {reason}",
        )

    deleted = 0
    failed = []

    for did in detector_ids:
        try:
            _api_delete(api_base, token, did)
            deleted += 1
            logger.info("Archive: deleted detector %s for %s/%s", did, environment, service)
        except RuntimeError as e:
            failed.append(did)
            logger.error("Archive: failed to delete detector %s: %s", did, e)

    # Remove muting rules
    try:
        unmute_service(realm, token, service, environment, state=state)
    except Exception as e:
        logger.warning("Archive: could not remove muting rules for %s/%s: %s", environment, service, e)

    # Mark archived in state
    state.archive(service, environment)

    if failed:
        return ArchiveResult(
            service=service, environment=environment,
            action="failed",
            detectors_deleted=deleted,
            reason=f"deleted {deleted}, failed to delete {len(failed)}: {failed}",
        )

    return ArchiveResult(
        service=service, environment=environment,
        action="archived",
        detectors_deleted=deleted,
        reason=reason,
    )


def archive_stale_services(
    realm: str,
    token: str,
    state: ProvisionerState,
    stale_days: float = DEFAULT_STALE_DAYS,
    dry_run: bool = True,
) -> list[ArchiveResult]:
    """
    Find and archive all services that have gone stale.
    Safe to run on a schedule — dry_run=True by default.
    """
    stale = check_stale_services(realm, token, state, stale_days)
    results = []

    for svc_state in stale:
        result = archive_service(
            realm=realm,
            token=token,
            service=svc_state.service,
            environment=svc_state.environment,
            state=state,
            dry_run=dry_run,
            reason=f"no spans seen in {stale_days:.0f} days",
        )
        results.append(result)

    return results


def format_archive_summary(results: list[ArchiveResult], dry_run: bool) -> str:
    if not results:
        return "\nNo stale services found."

    mode = "DRY RUN" if dry_run else "ARCHIVED"
    archived = [r for r in results if r.action == "archived"]
    failed = [r for r in results if r.action == "failed"]

    lines = [f"\n{mode}: {len(archived)} services archived, {len(failed)} failed"]

    for r in archived:
        lines.append(f"  ✓ {r.service} ({r.environment}) — {r.detectors_deleted} detectors deleted")
        lines.append(f"    {r.reason}")

    for r in failed:
        lines.append(f"  ✗ {r.service} ({r.environment}) — {r.reason}")

    return "\n".join(lines)
