"""
Detector deployer — pushes generated detectors to Splunk Observability
via the /v2/detector API.
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from templates.apm import DetectorTemplate

logger = logging.getLogger(__name__)

_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_MAX_RETRIES = 3


def _urlopen_with_retry(
    req: urllib.request.Request,
    timeout: int = 30,
    retry_statuses: frozenset = _RETRY_STATUSES,
) -> bytes:
    """Execute an HTTP request with exponential backoff on transient failures."""
    for attempt in range(_MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                chunks = []
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
                return b"".join(chunks)
        except urllib.error.HTTPError as e:
            body = b""
            try:
                body = e.read() or b""
            except Exception:
                pass
            if e.code in retry_statuses and attempt < _MAX_RETRIES:
                wait = 2 ** attempt  # 1, 2, 4 seconds
                logger.warning("HTTP %d — retrying in %ds (attempt %d/%d)",
                               e.code, wait, attempt + 1, _MAX_RETRIES)
                time.sleep(wait)
                continue
            raise RuntimeError(f"HTTP {e.code}: {body[:500].decode(errors='replace')}")
    raise RuntimeError("unreachable")  # pragma: no cover


def _validate_signalflow(api_base: str, token: str, program: str) -> str | None:
    """Validate SignalFlow program text via /v2/signalflow/validate.
    Returns an error string if invalid, or None if valid.
    """
    req = urllib.request.Request(
        f"{api_base}/v2/signalflow/validate",
        data=program.encode("utf-8"),
        headers={"X-SF-Token": token, "Content-Type": "text/plain"},
        method="POST",
    )
    try:
        # Only retry on rate-limit — 400 means invalid program (don't retry)
        _urlopen_with_retry(req, retry_statuses=frozenset({429, 503, 504}))
        return None
    except RuntimeError as e:
        return str(e)


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
    qs = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None})
    url = f"{api_base}{path}" + (f"?{qs}" if qs else "")
    req = urllib.request.Request(url, headers={"X-SF-Token": token, "Accept": "application/json"})
    return json.loads(_urlopen_with_retry(req).decode("utf-8"))


def _api_put(api_base: str, token: str, path: str, body: dict) -> dict:
    url = f"{api_base}{path}"
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"X-SF-Token": token, "Content-Type": "application/json"},
        method="PUT",
    )
    return json.loads(_urlopen_with_retry(req).decode("utf-8"))


def _api_post(api_base: str, token: str, path: str, body: dict) -> dict:
    url = f"{api_base}{path}"
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"X-SF-Token": token, "Content-Type": "application/json"},
        method="POST",
    )
    # POST is not idempotent — only retry on 429 (rate limit), not on 5xx
    return json.loads(_urlopen_with_retry(req, retry_statuses=frozenset({429})).decode("utf-8"))


def _normalize_signalflow(sf: str) -> str:
    """Strip unsupported arguments from SignalFlow before sending to the API.

    The /v2/detector API rejects:
      - lasting="..." on detect() — not supported in this API version
    Replace detect(when(...), lasting="5m") → detect(when(...))
    """
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
                validation_err = _validate_signalflow(api_base, token, payload["programText"])
                if validation_err:
                    logger.error("Invalid SignalFlow for %s: %s", template.name, validation_err)
                    results.append(DeployResult(
                        detector_name=template.name,
                        success=False,
                        error=f"SignalFlow validation failed: {validation_err}",
                    ))
                    continue
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
                validation_err = _validate_signalflow(api_base, token, payload["programText"])
                if validation_err:
                    logger.error("Invalid SignalFlow for %s: %s", template.name, validation_err)
                    results.append(DeployResult(
                        detector_name=template.name,
                        success=False,
                        error=f"SignalFlow validation failed: {validation_err}",
                    ))
                    continue
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
            validation_err = _validate_signalflow(api_base, token, payload["programText"])
            if validation_err:
                logger.error("Invalid SignalFlow for %s: %s", template.name, validation_err)
                results.append(DeployResult(
                    detector_name=template.name,
                    success=False,
                    error=f"SignalFlow validation failed: {validation_err}",
                ))
                continue
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
