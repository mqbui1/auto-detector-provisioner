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


def _build_detector_payload(template: DetectorTemplate, service: str, environment: str) -> dict:
    """Build the Splunk Observability detector API payload from a template."""
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
                "notifications": [],
            })

    if not rules:
        rules.append({
            "detectLabel": "Alert",
            "severity": template.severity,
            "disabled": False,
            "notifications": [],
        })

    return {
        "name": template.name,
        "description": template.description,
        "programOptions": {
            "minimumResolution": 60000,
            "maxDelay": 0,
        },
        "rules": rules,
        "tags": template.tags + [
            f"service:{service}",
            f"environment:{environment}",
            "auto-provisioned",
            f"stack:{template.tags[0]}" if template.tags else "stack:unknown",
        ],
        "visualizationOptions": {},
        "teams": [],
        "labelResolutions": {},
        "signalFlowText": template.signalflow,
    }


def deploy_detectors(
    realm: str,
    token: str,
    service: str,
    environment: str,
    detectors: list[DetectorTemplate],
    dry_run: bool = True,
) -> list[DeployResult]:
    """
    Deploy detectors to Splunk Observability.
    If dry_run=True, prints what would be deployed without making API calls.
    """
    api_base = f"https://api.{realm}.signalfx.com"
    results = []

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
            payload = _build_detector_payload(template, service, environment)
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
