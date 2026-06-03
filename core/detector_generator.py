"""
Detector generator — matches a ServiceProfile + ServiceBaseline to
detector templates and produces a list of DetectorTemplates ready for
dry-run review or deployment.
"""
from __future__ import annotations

import datetime
import html as _html
import logging
import re as _re
import textwrap
from typing import Any

from templates import TEMPLATE_REGISTRY
from templates.apm import APMTemplates, DetectorTemplate
from templates.database import DatabaseTemplates
from .discovery import ServiceProfile
from .baseline_learner import ServiceBaseline
from .metric_filter import (
    extract_metrics_from_signalflow,
    probe_existing_metrics,
    filter_detectors_by_metric_existence,
)

logger = logging.getLogger(__name__)

# Minimum confidence level to include in auto-deploy
# (low-confidence detectors are included in dry-run only)
AUTO_DEPLOY_MIN_CONFIDENCE = {"high", "medium"}


def generate_detectors(
    profile: ServiceProfile,
    baseline: ServiceBaseline | None = None,
    include_low_confidence: bool = False,
    realm: str = "",
    token: str = "",
    skip_metric_probe: bool = False,
) -> list[DetectorTemplate]:
    """
    Generate detector templates for a service based on its detected
    stack, frameworks, and libraries. Returns a list of DetectorTemplates.
    """
    service = profile.service
    environment = profile.environment
    detectors: list[DetectorTemplate] = []
    seen_names: set[str] = set()

    def _add(templates: list[DetectorTemplate]) -> None:
        for t in templates:
            if t.name in seen_names:
                continue
            if not include_low_confidence and t.confidence == "low":
                logger.debug("Skipping low-confidence detector: %s", t.name)
                continue
            seen_names.add(t.name)
            detectors.append(t)

    all_detected = profile.all_detected()
    all_stacks = set(profile.stacks)
    all_frameworks = set(profile.frameworks)

    # APM detectors always apply
    logger.info("Generator: adding APM detectors for %s/%s", environment, service)
    _add(APMTemplates.templates(service, environment, baseline))

    # Library techs that require direct span evidence (db.system / messaging.system)
    # to avoid false positives from shared infra metrics
    SPAN_GATED_LIBS = {"kafka", "redis", "postgresql", "mysql", "mongodb", "rabbitmq",
                       "elasticsearch", "cassandra", "dynamodb", "celery"}

    # Stack/framework/library detectors
    for tech in all_detected:
        template_cls = TEMPLATE_REGISTRY.get(tech)
        if not template_cls:
            logger.debug("No template for detected technology: %s", tech)
            continue

        confidence = profile.confidence.get(tech, "medium")
        if not include_low_confidence and confidence == "low":
            logger.debug("Skipping low-confidence technology: %s (%s)", tech, confidence)
            continue

        # For data-layer libs, require direct span evidence (db.system/messaging.system client spans)
        if tech in SPAN_GATED_LIBS and tech not in profile.direct_clients:
            logger.debug("Skipping %s templates — no direct client span evidence for %s", tech, service)
            continue

        logger.info("Generator: adding %s detectors for %s/%s (confidence=%s)", tech, environment, service, confidence)
        try:
            if template_cls is DatabaseTemplates and tech in ("postgresql", "mysql", "mongodb"):
                _add(template_cls.templates(service, environment, baseline, db_type=tech))
            else:
                _add(template_cls.templates(service, environment, baseline))
        except Exception as e:
            logger.warning("Generator: failed to generate %s templates: %s", tech, e)

    # Metric existence probe — drop detectors whose metrics have no data for this service
    if realm and token and not skip_metric_probe:
        api_base = f"https://api.{realm}.signalfx.com"
        # Collect all candidate metrics from all generated detectors
        all_candidates: set[str] = set()
        for det in detectors:
            all_candidates.update(extract_metrics_from_signalflow(det.signalflow))

        if all_candidates:
            existing = probe_existing_metrics(
                api_base, token, service, environment, all_candidates
            )
            before = len(detectors)
            detectors = filter_detectors_by_metric_existence(detectors, existing)
            dropped = before - len(detectors)
            if dropped:
                logger.info("Generator: metric probe dropped %d detectors with no data for %s/%s",
                            dropped, environment, service)

    logger.info("Generator: %d detectors generated for %s/%s", len(detectors), environment, service)
    return detectors


def format_dry_run_report(
    profile: ServiceProfile,
    detectors: list[DetectorTemplate],
    baseline: ServiceBaseline | None = None,
) -> str:
    """Format a human-readable dry-run report."""
    lines = []
    lines.append("=" * 70)
    lines.append(f"SERVICE: {profile.service}  ENV: {profile.environment}")
    lines.append("=" * 70)

    lines.append("\nDETECTED TECHNOLOGIES:")
    if profile.stacks:
        lines.append(f"  Stacks:     {', '.join(profile.stacks)}")
    if profile.frameworks:
        lines.append(f"  Frameworks: {', '.join(profile.frameworks)}")
    if profile.libraries:
        lines.append(f"  Libraries:  {', '.join(profile.libraries)}")
    if not profile.all_detected():
        lines.append("  (none detected — APM-only detectors will be generated)")

    if baseline:
        lines.append("\nLEARNED BASELINE:")
        if baseline.latency_mean_ms:
            lines.append(f"  Latency mean:   {baseline.latency_mean_ms:.1f}ms")
            lines.append(f"  Latency p99:    {baseline.latency_p99_ms:.1f}ms")
            lines.append(f"  Latency stddev: {baseline.latency_stddev_ms:.1f}ms")
        if baseline.error_rate_pct is not None:
            lines.append(f"  Error rate:     {baseline.error_rate_pct:.2f}%")
        lines.append(f"  Sample count:   {baseline.sample_count}")
        if not baseline.is_reliable():
            lines.append("  ⚠ Baseline has insufficient samples — using fixed thresholds")
    else:
        lines.append("\nBASELINE: Not available — using fixed best-practice thresholds")

    lines.append(f"\nDETECTORS TO CREATE ({len(detectors)}):")
    lines.append("-" * 70)

    by_tag: dict[str, list[DetectorTemplate]] = {}
    for d in detectors:
        primary_tag = d.tags[0] if d.tags else "other"
        by_tag.setdefault(primary_tag, []).append(d)

    for tag, tag_detectors in sorted(by_tag.items()):
        lines.append(f"\n  [{tag.upper()}]")
        for d in tag_detectors:
            conf_icon = {"high": "✓", "medium": "~", "low": "?"}.get(d.confidence, "?")
            thresh_icon = {"dynamic": "📈", "fixed": "📏", "hybrid": "🔀"}.get(d.threshold_type, "")
            lines.append(f"    {conf_icon} {thresh_icon} [{d.severity}] {d.name}")
            lines.append(f"       Signal:  {d.description}")
            if d.rationale:
                # Wrap rationale at 80 chars with consistent indent
                wrapped = textwrap.fill(d.rationale, width=80,
                                        initial_indent="       Rationale: ",
                                        subsequent_indent="                  ")
                lines.append(wrapped)

    lines.append("\nLEGEND:")
    lines.append("  Confidence: ✓ high  (metric exists + sufficient baseline data)")
    lines.append("              ~ medium (metric exists, baseline thin or absent)")
    lines.append("  Threshold:  📈 dynamic  — computed from your observed traffic baseline")
    lines.append("              📏 fixed    — Google SRE Book / OTel semantic conventions defaults")
    lines.append("  Sources:    Google SRE Book §6 (SLIs/SLOs/error budgets),")
    lines.append("              OpenTelemetry Semantic Conventions v1.24,")
    lines.append("              Splunk APM Detector Best Practices,")
    lines.append("              Python/CPython runtime instrumentation docs.")
    lines.append("")

    return "\n".join(lines)
