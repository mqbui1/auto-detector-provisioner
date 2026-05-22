"""
Muting manager — creates, lists, and deletes Splunk Observability muting rules
for a service. Handles deployment windows, maintenance periods, and
auto-mute on deploy events.

Muting rules are created via POST /v2/muterule and tied to detector tags
(service + environment) so they apply to all detectors for that service
without needing to know individual detector IDs.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

from .state import ProvisionerState

logger = logging.getLogger(__name__)


@dataclass
class MuteWindow:
    rule_id: str
    service: str
    environment: str
    reason: str
    start_time: float
    end_time: float
    created_at: float

    def is_active(self) -> bool:
        return self.start_time <= time.time() <= self.end_time

    def duration_minutes(self) -> int:
        return int((self.end_time - self.start_time) / 60)


def _api_post(api_base: str, token: str, path: str, body: dict) -> dict:
    url = f"{api_base}{path}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"X-SF-Token": token, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:500].decode()}")


def _api_delete(api_base: str, token: str, path: str) -> None:
    url = f"{api_base}{path}"
    req = urllib.request.Request(url, headers={"X-SF-Token": token}, method="DELETE")
    try:
        with urllib.request.urlopen(req, timeout=30):
            pass
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:300].decode()}")


def _api_get(api_base: str, token: str, path: str) -> dict:
    url = f"{api_base}{path}"
    req = urllib.request.Request(url, headers={"X-SF-Token": token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:300].decode()}")


def mute_service(
    realm: str,
    token: str,
    service: str,
    environment: str,
    duration_minutes: int,
    reason: str = "manual mute",
    state: ProvisionerState | None = None,
    dry_run: bool = False,
) -> MuteWindow | None:
    """
    Create a muting rule for all detectors associated with a service.
    Uses tag filters (service:<name> + environment:<env>) so it applies
    to every detector provisioned for that service without listing IDs.
    """
    api_base = f"https://api.{realm}.signalfx.com"
    now = time.time()
    start_ms = int(now * 1000)
    end_ms = int((now + duration_minutes * 60) * 1000)

    mute_rule = {
        "description": f"[auto-provisioner] {reason} — {service}/{environment}",
        "filters": [
            {"property": "sf_tags", "propertyValue": f"service:{service}", "NOT": False},
            {"property": "sf_tags", "propertyValue": f"environment:{environment}", "NOT": False},
        ],
        "startTime": start_ms,
        "stopTime": end_ms,
    }

    if dry_run:
        logger.info("[DRY RUN] Would mute %s/%s for %dm: %s", environment, service, duration_minutes, reason)
        return MuteWindow(
            rule_id="dry-run",
            service=service,
            environment=environment,
            reason=reason,
            start_time=now,
            end_time=now + duration_minutes * 60,
            created_at=now,
        )

    try:
        resp = _api_post(api_base, token, "/v2/muterule", mute_rule)
        rule_id = resp.get("id", "unknown")
        logger.info("Mute: created rule %s for %s/%s (%dm, reason: %s)",
                    rule_id, environment, service, duration_minutes, reason)

        if state:
            state.mute(service, environment, duration_minutes)

        return MuteWindow(
            rule_id=rule_id,
            service=service,
            environment=environment,
            reason=reason,
            start_time=now,
            end_time=now + duration_minutes * 60,
            created_at=now,
        )
    except RuntimeError as e:
        logger.error("Mute: failed to create rule for %s/%s: %s", environment, service, e)
        return None


def unmute_service(
    realm: str,
    token: str,
    service: str,
    environment: str,
    state: ProvisionerState | None = None,
) -> bool:
    """
    Delete all active muting rules for a service by listing rules and
    filtering by the service tag.
    """
    api_base = f"https://api.{realm}.signalfx.com"

    try:
        resp = _api_get(api_base, token, "/v2/muterule")
        rules = resp.get("results") or []
        deleted = 0

        for rule in rules:
            filters = rule.get("filters") or []
            svc_match = any(
                f.get("propertyValue") == f"service:{service}" for f in filters
            )
            env_match = any(
                f.get("propertyValue") == f"environment:{environment}" for f in filters
            )
            if svc_match and env_match:
                rule_id = rule.get("id")
                _api_delete(api_base, token, f"/v2/muterule/{rule_id}")
                logger.info("Mute: deleted rule %s for %s/%s", rule_id, environment, service)
                deleted += 1

        if state:
            state.unmute(service, environment)

        return deleted > 0

    except RuntimeError as e:
        logger.error("Unmute: failed for %s/%s: %s", environment, service, e)
        return False


def mute_on_deploy(
    realm: str,
    token: str,
    service: str,
    environment: str,
    deploy_duration_minutes: int = 15,
    state: ProvisionerState | None = None,
) -> MuteWindow | None:
    """
    Auto-mute a service during a deployment window.
    Called by CI/CD pipeline on deploy start. Automatically expires after
    deploy_duration_minutes — no manual cleanup needed.
    """
    return mute_service(
        realm=realm,
        token=token,
        service=service,
        environment=environment,
        duration_minutes=deploy_duration_minutes,
        reason=f"deployment in progress (auto-mute {deploy_duration_minutes}m)",
        state=state,
    )


def list_active_mutes(realm: str, token: str, environment: str | None = None) -> list[MuteWindow]:
    """List all active muting rules, optionally filtered by environment."""
    api_base = f"https://api.{realm}.signalfx.com"
    now = time.time()

    try:
        resp = _api_get(api_base, token, "/v2/muterule")
        rules = resp.get("results") or []
        windows = []

        for rule in rules:
            start_ms = rule.get("startTime", 0) / 1000
            end_ms = rule.get("stopTime", 0) / 1000

            if end_ms < now:
                continue  # already expired

            filters = rule.get("filters") or []
            svc = next(
                (f["propertyValue"].replace("service:", "")
                 for f in filters if f.get("propertyValue", "").startswith("service:")),
                "unknown",
            )
            env = next(
                (f["propertyValue"].replace("environment:", "")
                 for f in filters if f.get("propertyValue", "").startswith("environment:")),
                "unknown",
            )

            if environment and env != environment:
                continue

            windows.append(MuteWindow(
                rule_id=rule.get("id", ""),
                service=svc,
                environment=env,
                reason=rule.get("description", ""),
                start_time=start_ms,
                end_time=end_ms,
                created_at=rule.get("createdAt", now * 1000) / 1000,
            ))

        return windows

    except RuntimeError as e:
        logger.error("List mutes: failed: %s", e)
        return []


def format_mute_list(windows: list[MuteWindow]) -> str:
    if not windows:
        return "No active muting rules."

    lines = [f"\nACTIVE MUTING RULES ({len(windows)}):"]
    lines.append("-" * 60)
    now = time.time()

    for w in windows:
        remaining = int((w.end_time - now) / 60)
        lines.append(f"  {w.service} ({w.environment})")
        lines.append(f"    Rule ID:   {w.rule_id}")
        lines.append(f"    Reason:    {w.reason}")
        lines.append(f"    Remaining: {remaining}m")

    return "\n".join(lines)
