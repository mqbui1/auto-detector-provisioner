"""
Detector deployer — pushes generated detectors to Splunk Observability
via the /v2/detector API.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from dataclasses import dataclass

from templates.apm import DetectorTemplate

logger = logging.getLogger(__name__)

SEVERITY_TO_NOTIFICATION_SEVERITY = {
    "Critical": "Critical",
    "Major":    "Major",
    "Minor":    "Minor",
    "Warning":  "Warning",
    "Info":     "Info",
}


@dataclass
class DeployResult:
    detector_name: str
    success: bool
    detector_id: str | None = None
    error: str | None = None


def _api_get(api_base: str, token: str, path: str, params: dict | None = None) -> dict:
    import urllib.parse
    qs = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None})
    url = f"{api_base}{path}" + (f"?{qs}" if qs else "")
    req = urllib.request.Request(url, headers={"X-SF-Token": token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            chunks = []
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            return json.loads(b"".join(chunks).decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:300].decode()}")


def _api_put(api_base: str, token: str, path: str, body: dict) -> dict:
    url = f"{api_base}{path}"
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"X-SF-Token": token, "Content-Type": "application/json"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            chunks = []
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            return json.loads(b"".join(chunks).decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:500].decode()}")


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
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:500].decode()}")


def _normalize_signalflow(sf: str) -> str:
    """Strip unsupported arguments from SignalFlow before sending to the API.

    The /v2/detector API rejects:
      - lasting="..." on detect() — not supported in this API version
    Replace detect(when(...), lasting="5m") → detect(when(...))
    """
    import re
    # Remove , lasting="..." or , lasting='...' from detect() calls
    sf = re.sub(r",\s*lasting=['\"][^'\"]+['\"]", "", sf)
    return sf


def _build_notifications(integration_ids: list[str]) -> list[dict]:
    """Build notification objects from a list of integration IDs."""
    return [{"type": "Integration", "integrationId": iid} for iid in integration_ids]


def _build_detector_payload(
    template: DetectorTemplate,
    service: str,
    environment: str,
    notify: list[str] | None = None,
) -> dict:
    """Build the Splunk Observability detector API payload from a template."""
    notifications = _build_notifications(notify or [])
    rules = []

    # Parse publish labels from SignalFlow to build notification rules
    # Detectors typically publish "Critical", "Warning", "Anomaly"
    for label in ["Critical", "Warning", "Anomaly", "Info"]:
        if f'.publish("{label}")' in template.signalflow:
            severity = SEVERITY_TO_NOTIFICATION_SEVERITY.get(
                label if label != "Anomaly" else "Major", "Warning"
            )
            rules.append({
                "detectLabel": label,
                "severity": severity,
                "disabled": False,
                "notifications": notifications,
            })

    if not rules:
        rules.append({
            "detectLabel": "Alert",
            "severity": template.severity,
            "disabled": False,
            "notifications": notifications,
        })

    normalized = _normalize_signalflow(template.signalflow)
    return {
        "name": template.name,
        "description": template.description,
        "rules": rules,
        "tags": template.tags + [
            f"service:{service}",
            f"environment:{environment}",
            "auto-provisioned",
            f"stack:{template.tags[0]}" if template.tags else "stack:unknown",
        ],
        "visualizationOptions": {},
        "teams": [],
        "programText": normalized,
    }


def reconcile_detectors(
    realm: str,
    token: str,
    service: str,
    environment: str,
    detectors: list[DetectorTemplate],
    dry_run: bool = True,
    notify: list[str] | None = None,
) -> list[DeployResult]:
    """
    Reconcile detectors: fetch existing auto-provisioned detectors for the
    service, diff against fresh templates, and PUT only changed ones.
    Creates new ones if missing, skips unchanged ones.
    """
    api_base = f"https://api.{realm}.signalfx.com"
    results = []

    # Fetch existing detectors for this service tagged auto-provisioned
    try:
        resp = _api_get(api_base, token, "/v2/detector", {
            "limit": 200,
            "tags": "auto-provisioned",
        })
        existing = {
            d["name"]: d for d in resp.get("results", [])
            if f"service:{service}" in (d.get("tags") or [])
        }
    except RuntimeError as e:
        logger.warning("reconcile: failed to fetch existing detectors: %s", e)
        existing = {}

    for template in detectors:
        fresh_prog = _normalize_signalflow(template.signalflow).strip()
        existing_det = existing.get(template.name)

        if existing_det:
            deployed_prog = (existing_det.get("programText") or "").strip()
            if deployed_prog == fresh_prog:
                logger.info("[RECONCILE] Unchanged: %s", template.name)
                results.append(DeployResult(
                    detector_name=template.name,
                    success=True,
                    detector_id=existing_det["id"],
                ))
                continue

            # Program changed — update
            if dry_run:
                logger.info("[RECONCILE DRY RUN] Would update: %s", template.name)
                results.append(DeployResult(
                    detector_name=template.name,
                    success=True,
                    detector_id="dry-run-update",
                ))
                continue

            try:
                payload = _build_detector_payload(template, service, environment, notify=notify)
                updated = _api_put(api_base, token, f"/v2/detector/{existing_det['id']}", {
                    **existing_det,
                    "programText": fresh_prog,
                    "name": payload["name"],
                    "description": payload["description"],
                    "rules": payload["rules"],
                    "tags": payload["tags"],
                })
                logger.info("Updated detector: %s (id=%s)", template.name, updated.get("id"))
                results.append(DeployResult(
                    detector_name=template.name,
                    success=True,
                    detector_id=updated.get("id", existing_det["id"]),
                ))
            except RuntimeError as e:
                logger.error("Failed to update detector %s: %s", template.name, e)
                results.append(DeployResult(
                    detector_name=template.name,
                    success=False,
                    error=str(e),
                ))
        else:
            # New detector — create
            if dry_run:
                logger.info("[RECONCILE DRY RUN] Would create: %s", template.name)
                results.append(DeployResult(
                    detector_name=template.name,
                    success=True,
                    detector_id="dry-run-create",
                ))
                continue
            try:
                payload = _build_detector_payload(template, service, environment, notify=notify)
                response = _api_post(api_base, token, "/v2/detector", payload)
                detector_id = response.get("id", "unknown")
                logger.info("Created detector: %s (id=%s)", template.name, detector_id)
                results.append(DeployResult(
                    detector_name=template.name,
                    success=True,
                    detector_id=detector_id,
                ))
            except RuntimeError as e:
                logger.error("Failed to create detector %s: %s", template.name, e)
                results.append(DeployResult(
                    detector_name=template.name,
                    success=False,
                    error=str(e),
                ))

    return results


def deploy_detectors(
    realm: str,
    token: str,
    service: str,
    environment: str,
    detectors: list[DetectorTemplate],
    dry_run: bool = True,
    notify: list[str] | None = None,
) -> list[DeployResult]:
    """
    Deploy detectors to Splunk Observability.
    Checks for existing detectors by name to avoid duplicates — if a detector
    with the same name already exists it is updated (PUT) rather than created.
    If dry_run=True, prints what would happen without making API calls.
    """
    api_base = f"https://api.{realm}.signalfx.com"
    results = []

    # Fetch existing auto-provisioned detectors for this service once upfront
    existing_by_name: dict[str, dict] = {}
    if not dry_run:
        try:
            resp = _api_get(api_base, token, "/v2/detector", {
                "limit": 200, "tags": "auto-provisioned",
            })
            for d in resp.get("results", []):
                if f"service:{service}" in (d.get("tags") or []):
                    existing_by_name[d["name"]] = d
        except RuntimeError as e:
            logger.warning("deploy: could not check existing detectors for %s: %s", service, e)

    for template in detectors:
        if dry_run:
            logger.info("[DRY RUN] Would create detector: %s", template.name)
            results.append(DeployResult(
                detector_name=template.name,
                success=True,
                detector_id="dry-run",
            ))
            continue

        try:
            payload = _build_detector_payload(template, service, environment, notify=notify)
            existing = existing_by_name.get(template.name)
            if existing:
                # Update in-place to avoid duplicate
                updated = _api_put(api_base, token, f"/v2/detector/{existing['id']}", {
                    **existing,
                    "programText": payload["programText"],
                    "name": payload["name"],
                    "description": payload["description"],
                    "rules": payload["rules"],
                    "tags": payload["tags"],
                })
                detector_id = updated.get("id", existing["id"])
                logger.info("Updated existing detector: %s (id=%s)", template.name, detector_id)
            else:
                response = _api_post(api_base, token, "/v2/detector", payload)
                detector_id = response.get("id", "unknown")
                logger.info("Created detector: %s (id=%s)", template.name, detector_id)
            results.append(DeployResult(
                detector_name=template.name,
                success=True,
                detector_id=detector_id,
            ))
        except RuntimeError as e:
            logger.error("Failed to deploy detector %s: %s", template.name, e)
            results.append(DeployResult(
                detector_name=template.name,
                success=False,
                error=str(e),
            ))

    return results


def format_deploy_summary(results: list[DeployResult], dry_run: bool) -> str:
    lines = []
    mode = "DRY RUN" if dry_run else "DEPLOYED"
    succeeded = [r for r in results if r.success]
    failed = [r for r in results if not r.success]

    lines.append(f"\n{mode} SUMMARY: {len(succeeded)}/{len(results)} detectors {'would be created' if dry_run else 'created'}")

    if failed:
        lines.append(f"\nFAILED ({len(failed)}):")
        for r in failed:
            lines.append(f"  ✗ {r.detector_name}: {r.error}")

    if succeeded and not dry_run:
        lines.append(f"\nCREATED ({len(succeeded)}):")
        for r in succeeded:
            lines.append(f"  ✓ {r.detector_name} (id={r.detector_id})")

    return "\n".join(lines)
