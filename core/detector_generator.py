"""
Detector generator — matches a ServiceProfile + ServiceBaseline to
detector templates and produces a list of DetectorTemplates ready for
dry-run review or deployment.
"""
from __future__ import annotations

import logging
from typing import Any

from templates import TEMPLATE_REGISTRY
from templates.apm import APMTemplates, DetectorTemplate
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
            from templates.database import DatabaseTemplates
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


def format_html_report(
    profiles_detectors: list[tuple["ServiceProfile", list["DetectorTemplate"], "ServiceBaseline | None"]],
    realm: str,
    environment: str | None,
) -> str:
    """Render a self-contained HTML report for all services and their detectors."""
    import html as _html
    import datetime

    def h(s: str) -> str:
        return _html.escape(str(s))

    conf_label = {"high": ("HIGH", "#22c55e"), "medium": ("MED", "#f59e0b"), "low": ("LOW", "#94a3b8")}
    thresh_label = {"dynamic": ("dynamic", "#818cf8"), "fixed": ("fixed", "#38bdf8"), "hybrid": ("hybrid", "#fb923c")}
    sev_label = {"Critical": "#ef4444", "Major": "#f97316", "Warning": "#facc15", "Minor": "#a3e635", "Info": "#60a5fa"}
    tag_colors = {
        "apm": "#0ea5e9", "go": "#06b6d4", "nodejs": "#84cc16", "dotnet": "#818cf8",
        "python": "#f59e0b", "rust": "#fb923c", "jvm": "#f43f5e", "grpc": "#a78bfa",
        "kafka": "#fb7185", "redis": "#34d399", "dotnet": "#818cf8", "istio": "#38bdf8",
    }

    total_detectors = sum(len(dets) for _, dets, _ in profiles_detectors)
    generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    lines = ["""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Auto-Detector Provisioner Report</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
       background:#0f172a;color:#e2e8f0;line-height:1.5;font-size:14px}
  a{color:#60a5fa;text-decoration:none}
  .header{background:linear-gradient(135deg,#1e293b,#0f172a);
          border-bottom:1px solid #334155;padding:14px 32px;
          display:flex;align-items:center;justify-content:space-between;
          height:56px}
  .header h1{font-size:18px;font-weight:700;color:#f8fafc;letter-spacing:-.3px}
  .header .meta{font-size:11px;color:#94a3b8;text-align:right;line-height:1.6}
  .summary-bar{background:#1e293b;border-bottom:1px solid #334155;
               padding:10px 32px;display:flex;gap:32px;align-items:center;
               height:52px}
  .stat{display:flex;flex-direction:column;align-items:center}
  .stat .n{font-size:24px;font-weight:700;color:#f8fafc}
  .stat .l{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px}
  .toc{background:#1e293b;border-right:1px solid #334155;
       width:220px;position:fixed;top:0;left:0;height:100vh;overflow-y:auto;
       padding:112px 0 24px;z-index:10}
  .toc-item{padding:6px 16px;font-size:12px;color:#94a3b8;cursor:pointer;
            display:flex;align-items:center;gap:8px;border-left:2px solid transparent}
  .toc-item:hover{color:#e2e8f0;background:#334155}
  .toc-item .count{margin-left:auto;background:#334155;border-radius:9px;
                   padding:1px 7px;font-size:11px;color:#94a3b8}
  .main{margin-left:220px;padding:120px 32px 48px}
  .service-card{background:#1e293b;border:1px solid #334155;border-radius:12px;
                margin-bottom:24px;overflow:hidden}
  .service-header{padding:16px 20px;display:flex;align-items:center;gap:12px;
                  border-bottom:1px solid #334155;background:#0f172a}
  .service-name{font-size:16px;font-weight:700;color:#f8fafc}
  .service-env{font-size:11px;color:#64748b;background:#334155;
               padding:2px 8px;border-radius:4px}
  .tech-tags{display:flex;gap:6px;flex-wrap:wrap;margin-left:auto}
  .tag{font-size:11px;font-weight:600;padding:2px 8px;border-radius:4px;
       background:#334155;color:#cbd5e1}
  .baseline-info{padding:8px 20px;font-size:12px;color:#64748b;
                 background:#0f172a;border-bottom:1px solid #1e293b}
  .detectors{padding:12px 20px;display:flex;flex-direction:column;gap:10px}
  .detector{background:#0f172a;border:1px solid #334155;border-radius:8px;
            padding:14px 16px}
  .detector-header{display:flex;align-items:center;gap:8px;margin-bottom:8px}
  .detector-name{font-weight:600;color:#f1f5f9;font-size:13px;flex:1}
  .badge{font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;
         text-transform:uppercase;letter-spacing:.4px}
  .signal{font-size:12px;color:#94a3b8;margin-bottom:8px}
  .rationale{font-size:12px;color:#64748b;line-height:1.6;
             border-left:2px solid #334155;padding-left:10px}
  .rationale .source{color:#60a5fa;font-style:italic}
  .signalflow{background:#020617;border:1px solid #1e293b;border-radius:6px;
              padding:10px 12px;font-family:'JetBrains Mono',Consolas,monospace;
              font-size:11px;color:#7dd3fc;margin-top:8px;
              white-space:pre-wrap;display:none}
  .toggle-sf{font-size:11px;color:#475569;cursor:pointer;margin-top:6px;
             display:inline-flex;align-items:center;gap:4px}
  .toggle-sf:hover{color:#94a3b8}
  .legend{background:#1e293b;border:1px solid #334155;border-radius:8px;
          padding:16px 20px;margin-top:32px;font-size:12px;color:#64748b}
  .legend h3{color:#94a3b8;margin-bottom:8px;font-size:13px}
  .legend-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px 24px}
  @media(max-width:768px){.toc{display:none}.main{margin-left:0}}
</style>
</head>
<body>"""]

    lines.append(f"""
<div class="header" style="position:fixed;top:0;left:0;right:0;z-index:20">
  <h1>⚡ Auto-Detector Provisioner Report</h1>
  <div class="meta">
    Realm: <strong>{h(realm)}</strong> &nbsp;|&nbsp;
    Env: <strong>{h(environment or 'all')}</strong><br>
    Generated: {generated_at}<br>
    Mode: <span style="color:#f59e0b;font-weight:600">DRY RUN</span>
  </div>
</div>""")

    lines.append(f"""
<div class="summary-bar" style="position:fixed;top:56px;left:0;right:0;z-index:15;padding-left:252px">
  <div class="stat"><span class="n">{len(profiles_detectors)}</span><span class="l">Services</span></div>
  <div class="stat"><span class="n">{total_detectors}</span><span class="l">Detectors</span></div>
  <div class="stat"><span class="n">{sum(1 for _,ds,_ in profiles_detectors for d in ds if d.threshold_type=="dynamic")}</span><span class="l">Dynamic</span></div>
  <div class="stat"><span class="n">{sum(1 for _,ds,_ in profiles_detectors for d in ds if d.threshold_type=="fixed")}</span><span class="l">Fixed</span></div>
</div>""")

    # TOC
    lines.append('<nav class="toc">')
    for profile, detectors, _ in profiles_detectors:
        svc_id = h(profile.service.replace(".", "-"))
        lines.append(
            f'<div class="toc-item" onclick="document.getElementById(\'{svc_id}\').scrollIntoView({{behavior:\'smooth\'}})">'
            f'{h(profile.service)}'
            f'<span class="count">{len(detectors)}</span></div>'
        )
    lines.append("</nav>")

    lines.append('<main class="main">')

    # Badge guide — inline at top before service cards
    lines.append("""
<div class="legend" style="margin-bottom:24px">
  <div style="display:flex;align-items:baseline;gap:12px;margin-bottom:12px">
    <h3 style="color:#94a3b8;font-size:13px;font-weight:600">Badge Guide</h3>
    <span style="font-size:11px;color:#475569">Each detector shows: severity &nbsp;·&nbsp; confidence &nbsp;·&nbsp; threshold type</span>
  </div>
  <div style="display:flex;gap:32px;flex-wrap:wrap">
    <div>
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#475569;margin-bottom:6px">Severity</div>
      <div style="display:flex;flex-direction:column;gap:4px;font-size:12px">
        <div><span class="badge" style="background:#ef444422;color:#ef4444;border:1px solid #ef444444">Critical</span> &nbsp;service down or data loss imminent</div>
        <div><span class="badge" style="background:#f9731622;color:#f97316;border:1px solid #f9731644">Major</span> &nbsp;significant degradation, users affected</div>
        <div><span class="badge" style="background:#f59e0b22;color:#f59e0b;border:1px solid #f59e0b44">Warning</span> &nbsp;early signal, investigate soon</div>
      </div>
    </div>
    <div>
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#475569;margin-bottom:6px">Confidence</div>
      <div style="display:flex;flex-direction:column;gap:4px;font-size:12px">
        <div><span class="badge" style="background:#22c55e22;color:#22c55e;border:1px solid #22c55e44">High</span> &nbsp;metric confirmed, baseline sufficient</div>
        <div><span class="badge" style="background:#f59e0b22;color:#f59e0b;border:1px solid #f59e0b44">Med</span> &nbsp;metric exists, baseline thin or absent</div>
      </div>
    </div>
    <div>
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#475569;margin-bottom:6px">Threshold Type</div>
      <div style="display:flex;flex-direction:column;gap:4px;font-size:12px">
        <div><span class="badge" style="background:#818cf822;color:#818cf8;border:1px solid #818cf844">Dynamic</span> &nbsp;learned from your traffic (mean ± σ), auto-tunes</div>
        <div><span class="badge" style="background:#38bdf822;color:#38bdf8;border:1px solid #38bdf844">Fixed</span> &nbsp;industry defaults (SRE Book / OTel); tune with data</div>
      </div>
    </div>
  </div>
</div>""")

    for profile, detectors, baseline in profiles_detectors:
        svc_id = h(profile.service.replace(".", "-"))
        lines.append(f'<div class="service-card" id="{svc_id}">')

        # Service header
        all_tech = profile.stacks + profile.frameworks + profile.libraries
        tech_tags_html = "".join(
            f'<span class="tag" style="background:{tag_colors.get(t,"#334155")};color:#fff">{h(t)}</span>'
            for t in all_tech
        ) or '<span class="tag">APM only</span>'
        lines.append(
            f'<div class="service-header">'
            f'<span class="service-name">{h(profile.service)}</span>'
            f'<span class="service-env">{h(profile.environment)}</span>'
            f'<div class="tech-tags">{tech_tags_html}</div>'
            f'</div>'
        )

        # Baseline
        if baseline and baseline.is_reliable():
            err_pct = baseline.error_rate_pct or 0.0
            bl_text = (f"Baseline: latency p99={baseline.latency_p99_ms:.0f}ms "
                       f"error_rate={err_pct:.2f}% "
                       f"samples={baseline.sample_count} — dynamic thresholds active")
        else:
            bl_text = "Baseline: insufficient samples — fixed best-practice thresholds"
        lines.append(f'<div class="baseline-info">{h(bl_text)}</div>')

        # Detectors
        lines.append('<div class="detectors">')
        for det in detectors:
            conf_text, conf_color = conf_label.get(det.confidence, ("?", "#94a3b8"))
            thresh_text, thresh_color = thresh_label.get(det.threshold_type, ("fixed", "#38bdf8"))
            sev_color = sev_label.get(det.severity, "#94a3b8")
            det_id = h(f"{profile.service}-{det.name}".replace(" ", "-").replace("[", "").replace("]", ""))

            tag_badges = "".join(
                f'<span class="badge" style="background:{tag_colors.get(t,"#334155")}22;'
                f'color:{tag_colors.get(t,"#94a3b8")};border:1px solid {tag_colors.get(t,"#334155")}44">'
                f'{h(t)}</span>'
                for t in det.tags
            )

            # Strip [service] prefix from name for display (service is shown in card header)
            import re as _re
            display_name = _re.sub(r'^\[.*?\]\s*', '', det.name)
            # Simplify description: strip "Service X " prefix from description
            display_desc = _re.sub(rf'^Service\s+{_re.escape(profile.service)}\s+', '', det.description)

            lines.append(f'<div class="detector">')
            lines.append(
                f'<div class="detector-header">'
                f'<span class="detector-name">{h(display_name)}</span>'
                f'<span class="badge" style="background:{sev_color}22;color:{sev_color};border:1px solid {sev_color}44">{h(det.severity)}</span>'
                f'<span class="badge" style="background:{conf_color}22;color:{conf_color};border:1px solid {conf_color}44">{conf_text}</span>'
                f'<span class="badge" style="background:{thresh_color}22;color:{thresh_color};border:1px solid {thresh_color}44">{thresh_text}</span>'
                f'{tag_badges}'
                f'</div>'
            )
            lines.append(f'<div class="signal">{h(display_desc)}</div>')

            if det.rationale:
                # Split out source citations (sentences containing "Source:")
                rationale_parts = det.rationale.split("Source:")
                main_rationale = rationale_parts[0].strip()
                source_text = ("Source: " + rationale_parts[1].strip()) if len(rationale_parts) > 1 else ""
                lines.append(
                    f'<div class="rationale">{h(main_rationale)}'
                    + (f'<br><span class="source">{h(source_text)}</span>' if source_text else "")
                    + "</div>"
                )

            sf_escaped = h(det.signalflow)
            lines.append(
                f'<span class="toggle-sf" onclick="var e=document.getElementById(\'{det_id}-sf\');'
                f'e.style.display=e.style.display===\'block\'?\'none\':\'block\';'
                f'this.textContent=e.style.display===\'block\'?\'▾ hide SignalFlow\':\'▸ show SignalFlow\'">'
                f'▸ show SignalFlow</span>'
                f'<div class="signalflow" id="{det_id}-sf">{sf_escaped}</div>'
            )
            lines.append("</div>")  # detector

        lines.append("</div>")  # detectors
        lines.append("</div>")  # service-card

    lines.append("</main>\n</body>\n</html>")

    return "\n".join(lines)


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
                import textwrap
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
