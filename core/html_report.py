"""
HTML report generator — produces a self-contained interactive HTML report
with per-detector checkboxes and a Deploy Selected button.

The report embeds all detector data as JSON and talks to a local HTTP server
(started by provision.py --html-report) to execute deployments.
"""
from __future__ import annotations

import html
import json
import re
from typing import Any

from templates.apm import DetectorTemplate
from .discovery import ServiceProfile
from .baseline_learner import ServiceBaseline


# ── Helpers ───────────────────────────────────────────────────────────────────

def _det_id(service: str, det_name: str) -> str:
    """Stable DOM/JSON id for a detector."""
    slug = re.sub(r"[^a-z0-9]+", "-", (service + "-" + det_name).lower()).strip("-")
    return slug


def _severity_style(sev: str) -> str:
    return {
        "Critical": "background:#ef444422;color:#ef4444;border:1px solid #ef444444",
        "Major":    "background:#f9731622;color:#f97316;border:1px solid #f9731644",
        "Minor":    "background:#f59e0b22;color:#f59e0b;border:1px solid #f59e0b44",
        "Warning":  "background:#f59e0b22;color:#f59e0b;border:1px solid #f59e0b44",
        "Info":     "background:#22c55e22;color:#22c55e;border:1px solid #22c55e44",
    }.get(sev, "background:#33415522;color:#94a3b8;border:1px solid #33415544")


def _conf_style(conf: str) -> tuple[str, str]:
    """Returns (label, style)."""
    return {
        "high":   ("HIGH",   "background:#22c55e22;color:#22c55e;border:1px solid #22c55e44"),
        "medium": ("MED",    "background:#f59e0b22;color:#f59e0b;border:1px solid #f59e0b44"),
        "low":    ("LOW",    "background:#ef444422;color:#ef4444;border:1px solid #ef444444"),
    }.get(conf, ("?", "background:#33415522;color:#94a3b8"))


def _thresh_style(tt: str) -> tuple[str, str]:
    return {
        "dynamic": ("Dynamic", "background:#818cf822;color:#818cf8;border:1px solid #818cf844"),
        "fixed":   ("Fixed",   "background:#38bdf822;color:#38bdf8;border:1px solid #38bdf844"),
        "hybrid":  ("Hybrid",  "background:#a78bfa22;color:#a78bfa;border:1px solid #a78bfa44"),
    }.get(tt, (tt, "background:#33415522;color:#94a3b8"))


_TAG_COLORS = {
    "apm":        "#0ea5e9", "jvm":        "#f97316", "nodejs":   "#84cc16",
    "python":     "#f59e0b", "dotnet":     "#818cf8", "go":       "#34d399",
    "rust":       "#fb923c", "kubernetes": "#60a5fa", "kafka":    "#facc15",
    "redis":      "#f87171", "nginx":      "#a3e635", "istio":    "#38bdf8",
    "grpc":       "#a78bfa", "flask":      "#4ade80", "django":   "#22d3ee",
    "fastapi":    "#86efac", "spring_boot":"#4ade80", "aws":      "#fb923c",
    "latency":    "#334155", "error_rate": "#334155", "availability": "#334155",
    "event_loop": "#334155", "heap":       "#334155", "gc":       "#334155",
}

def _tag_style(tag: str) -> str:
    color = _TAG_COLORS.get(tag, "#64748b")
    if color.startswith("#3341"):  # subdued tags
        return "background:#33415522;color:#94a3b8;border:1px solid #33415544"
    return f"background:{color}22;color:{color};border:1px solid {color}44"


# ── CSS ───────────────────────────────────────────────────────────────────────

_CSS = """
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
       background:#0f172a;color:#e2e8f0;line-height:1.5;font-size:14px}
  a{color:#60a5fa;text-decoration:none}
  .header{background:linear-gradient(135deg,#1e293b,#0f172a);
          border-bottom:1px solid #334155;padding:14px 32px;
          display:flex;align-items:center;justify-content:space-between;
          height:56px;position:fixed;top:0;left:0;right:0;z-index:20}
  .header h1{font-size:18px;font-weight:700;color:#f8fafc;letter-spacing:-.3px}
  .header .meta{font-size:11px;color:#94a3b8;text-align:right;line-height:1.6}
  .action-bar{background:#1e293b;border-bottom:1px solid #334155;
              padding:10px 32px;display:flex;gap:16px;align-items:center;
              height:52px;position:fixed;top:56px;left:0;right:0;z-index:15;
              padding-left:252px}
  .stat{display:flex;flex-direction:column;align-items:center}
  .stat .n{font-size:22px;font-weight:700;color:#f8fafc}
  .stat .l{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px}
  .sep{width:1px;height:32px;background:#334155}
  .btn{padding:8px 18px;border-radius:6px;font-size:13px;font-weight:600;
       cursor:pointer;border:none;display:inline-flex;align-items:center;gap:6px;
       transition:all .15s}
  .btn-deploy{background:#2563eb;color:#fff}
  .btn-deploy:hover{background:#1d4ed8}
  .btn-deploy:disabled{background:#1e3a5f;color:#475569;cursor:not-allowed}
  .btn-sm{background:#334155;color:#94a3b8;padding:5px 10px;font-size:11px;
          border-radius:4px;cursor:pointer;border:none}
  .btn-sm:hover{background:#475569;color:#e2e8f0}
  .sel-count{font-size:12px;color:#64748b;margin-left:4px}
  .toc{background:#1e293b;border-right:1px solid #334155;
       width:220px;position:fixed;top:0;left:0;height:100vh;overflow-y:auto;
       padding:116px 0 24px;z-index:10}
  .toc-item{padding:6px 16px;font-size:12px;color:#94a3b8;cursor:pointer;
            display:flex;align-items:center;gap:8px;border-left:2px solid transparent}
  .toc-item:hover{color:#e2e8f0;background:#334155}
  .toc-item .count{margin-left:auto;background:#334155;border-radius:9px;
                   padding:1px 7px;font-size:11px;color:#94a3b8}
  .main{margin-left:220px;padding:120px 32px 48px}
  .service-card{background:#1e293b;border:1px solid #334155;border-radius:12px;
                margin-bottom:24px;overflow:hidden}
  .service-header{padding:14px 20px;display:flex;align-items:center;gap:10px;
                  border-bottom:1px solid #334155;background:#0f172a}
  .svc-check{width:16px;height:16px;accent-color:#2563eb;cursor:pointer;flex-shrink:0}
  .service-name{font-size:15px;font-weight:700;color:#f8fafc}
  .service-env{font-size:11px;color:#64748b;background:#334155;
               padding:2px 8px;border-radius:4px}
  .tech-tags{display:flex;gap:6px;flex-wrap:wrap;margin-left:auto}
  .tag{font-size:11px;font-weight:600;padding:2px 8px;border-radius:4px}
  .baseline-info{padding:7px 20px;font-size:12px;color:#64748b;
                 background:#0f172a;border-bottom:1px solid #1e293b}
  .detectors{padding:12px 20px;display:flex;flex-direction:column;gap:10px}
  .detector{background:#0f172a;border:1px solid #334155;border-radius:8px;
            padding:12px 14px;transition:border-color .15s}
  .detector.unchecked{opacity:.45;border-color:#1e293b}
  .detector-header{display:flex;align-items:center;gap:8px;margin-bottom:8px}
  .det-check{width:15px;height:15px;accent-color:#2563eb;cursor:pointer;flex-shrink:0}
  .detector-name{font-weight:600;color:#f1f5f9;font-size:13px;flex:1}
  .badge{font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;
         text-transform:uppercase;letter-spacing:.4px}
  .signal{font-size:12px;color:#94a3b8;margin-bottom:4px}
  .thresh-reason{font-size:11px;margin-bottom:6px;padding:3px 8px;border-radius:4px;display:inline-block}
  .thresh-reason.dynamic{background:#818cf811;color:#818cf8;border:1px solid #818cf833}
  .thresh-reason.fixed{background:#38bdf811;color:#38bdf8;border:1px solid #38bdf833}
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
  /* Deploy modal */
  .modal-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);
                 z-index:100;align-items:center;justify-content:center}
  .modal-overlay.open{display:flex}
  .modal{background:#1e293b;border:1px solid #334155;border-radius:12px;
         padding:24px;min-width:480px;max-width:680px;width:90%}
  .modal h2{font-size:16px;font-weight:700;color:#f8fafc;margin-bottom:16px}
  .deploy-log{background:#020617;border:1px solid #1e293b;border-radius:6px;
              padding:12px;font-family:Consolas,monospace;font-size:12px;
              color:#7dd3fc;max-height:320px;overflow-y:auto;
              white-space:pre-wrap;min-height:80px}
  .modal-footer{margin-top:16px;display:flex;gap:8px;justify-content:flex-end}
  .btn-close{background:#334155;color:#e2e8f0;padding:8px 18px;border-radius:6px;
             font-size:13px;font-weight:600;cursor:pointer;border:none}
  .btn-close:hover{background:#475569}
  @media(max-width:768px){.toc{display:none}.main{margin-left:0}}
"""

# ── JS ────────────────────────────────────────────────────────────────────────

_JS = """
// ── Filter bar ────────────────────────────────────────────────────────────────
function applyFilters(){
  var svcFilter = (document.getElementById('filter-svc') || {}).value || '';
  var sevFilter = (document.getElementById('filter-sev') || {}).value || '';
  var typeFilter = (document.getElementById('filter-type') || {}).value || '';
  svcFilter = svcFilter.toLowerCase();

  document.querySelectorAll('.service-card').forEach(function(card){
    var svcName = (card.querySelector('.service-name') || {}).textContent || '';
    var svcMatch = !svcFilter || svcName.toLowerCase().includes(svcFilter);

    var visibleDets = 0;
    card.querySelectorAll('.detector').forEach(function(det){
      var sev = (det.querySelector('.sev-badge') || {}).textContent || '';
      var type = det.dataset.thresholdType || '';
      var sevMatch = !sevFilter || sev.toLowerCase() === sevFilter.toLowerCase();
      var typeMatch = !typeFilter || type === typeFilter;
      var show = svcMatch && sevMatch && typeMatch;
      det.style.display = show ? '' : 'none';
      if(show) visibleDets++;
    });
    card.style.display = (svcMatch && visibleDets > 0) ? '' : 'none';
  });
  updateSelCount();
}

// ── Checkbox state ────────────────────────────────────────────────────────────
function updateSelCount(){
  const total = document.querySelectorAll('.det-check:not([style*="display: none"])').length;
  const checked = document.querySelectorAll('.det-check:checked:not([style*="display: none"])').length;
  document.getElementById('sel-count').textContent = checked + ' / ' + total + ' selected';
  document.getElementById('btn-deploy').disabled = checked === 0;
}

function syncServiceCheck(svcId){
  const svcCard = document.getElementById(svcId);
  const dets = svcCard.querySelectorAll('.det-check');
  const svcBox = svcCard.querySelector('.svc-check');
  const checkedCount = Array.from(dets).filter(c=>c.checked).length;
  svcBox.checked = checkedCount === dets.length;
  svcBox.indeterminate = checkedCount > 0 && checkedCount < dets.length;
}

document.addEventListener('DOMContentLoaded', function(){
  // Service-level checkbox toggles all its detectors
  document.querySelectorAll('.svc-check').forEach(function(svcBox){
    svcBox.addEventListener('change', function(){
      const card = svcBox.closest('.service-card');
      card.querySelectorAll('.det-check').forEach(function(cb){
        cb.checked = svcBox.checked;
        cb.closest('.detector').classList.toggle('unchecked', !svcBox.checked);
      });
      updateSelCount();
    });
  });

  // Detector checkbox dims the row and syncs service checkbox
  document.querySelectorAll('.det-check').forEach(function(cb){
    cb.addEventListener('change', function(){
      cb.closest('.detector').classList.toggle('unchecked', !cb.checked);
      syncServiceCheck(cb.closest('.service-card').id);
      updateSelCount();
    });
  });

  // Select all / none
  document.getElementById('btn-all').addEventListener('click', function(){
    document.querySelectorAll('.det-check').forEach(function(cb){ cb.checked=true; cb.closest('.detector').classList.remove('unchecked'); });
    document.querySelectorAll('.svc-check').forEach(function(cb){ cb.checked=true; cb.indeterminate=false; });
    updateSelCount();
  });
  document.getElementById('btn-none').addEventListener('click', function(){
    document.querySelectorAll('.det-check').forEach(function(cb){ cb.checked=false; cb.closest('.detector').classList.add('unchecked'); });
    document.querySelectorAll('.svc-check').forEach(function(cb){ cb.checked=false; cb.indeterminate=false; });
    updateSelCount();
  });

  updateSelCount();
});

// ── SignalFlow toggle ─────────────────────────────────────────────────────────
function toggleSF(id, btn){
  var e = document.getElementById(id);
  var show = e.style.display !== 'block';
  e.style.display = show ? 'block' : 'none';
  btn.textContent = show ? '▾ hide SignalFlow' : '▸ show SignalFlow';
}

// ── Deploy ────────────────────────────────────────────────────────────────────
var SERVER_PORT = __SERVER_PORT__;

function openDeployModal(){
  var selected = [];
  document.querySelectorAll('.det-check:checked').forEach(function(cb){
    selected.push(cb.dataset.id);
  });
  if(selected.length === 0){ alert('No detectors selected.'); return; }

  var log = document.getElementById('deploy-log');
  log.textContent = 'Connecting to local provisioner...\\n';
  document.getElementById('modal-overlay').classList.add('open');
  document.getElementById('btn-modal-close').disabled = true;
  document.getElementById('btn-modal-close').textContent = 'Deploying...';

  fetch('http://localhost:' + SERVER_PORT + '/deploy', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({selected: selected})
  })
  .then(function(r){ return r.json(); })
  .then(function(data){
    log.textContent = '';
    (data.results || []).forEach(function(r){
      log.textContent += (r.success ? '✓ ' : '✗ ') + r.name +
        (r.detector_id && r.detector_id !== 'dry-run' ? '  (id: ' + r.detector_id + ')' : '') +
        (r.error ? '  ERROR: ' + r.error : '') + '\\n';
    });
    log.textContent += '\\n' + (data.message || '');
    document.getElementById('btn-modal-close').disabled = false;
    document.getElementById('btn-modal-close').textContent = 'Close';
  })
  .catch(function(err){
    log.textContent += 'Error: ' + err + '\\n\\nMake sure provision.py is still running (--html-report keeps the server alive).';
    document.getElementById('btn-modal-close').disabled = false;
    document.getElementById('btn-modal-close').textContent = 'Close';
  });
}

function closeModal(){
  document.getElementById('modal-overlay').classList.remove('open');
}
"""


# ── Per-detector HTML ─────────────────────────────────────────────────────────

def _detector_html(service: str, det: DetectorTemplate) -> str:
    det_id = _det_id(service, det.name)
    sf_id = det_id + "-sf"
    conf_label, conf_style = _conf_style(det.confidence)
    thresh_label, thresh_style = _thresh_style(det.threshold_type)
    sev_style = _severity_style(det.severity)

    badges = (
        f'<span class="badge sev-badge" style="{sev_style}">{html.escape(det.severity)}</span>'
        f'<span class="badge" style="{conf_style}">{conf_label}</span>'
        f'<span class="badge" style="{thresh_style}">{thresh_label}</span>'
    )
    for tag in det.tags:
        badges += f'<span class="badge" style="{_tag_style(tag)}">{html.escape(tag)}</span>'

    # Threshold reason line — one-liner explaining why dynamic or fixed
    if det.threshold_type == "dynamic":
        # Extract the threshold values from the description (e.g. "Warn: >10.7ms  Anomaly: >12.2ms")
        thresh_match = re.search(r'(Warn[^<\n]+)', det.description)
        thresh_detail = thresh_match.group(1) if thresh_match else ""
        thresh_reason = (
            f'<div class="thresh-reason dynamic">&#128200; Thresholds learned from observed traffic baseline'
            + (f' &mdash; {html.escape(thresh_detail)}' if thresh_detail else '')
            + '</div>'
        )
    else:
        thresh_reason = (
            '<div class="thresh-reason fixed">&#128207; Fixed industry-default thresholds '
            '(no sufficient baseline data yet &mdash; will upgrade to Dynamic once enough traffic is observed)</div>'
        )

    rationale_html = ""
    if det.rationale:
        # Split on "Source:" to style it separately
        parts = det.rationale.split("Source:", 1)
        body = html.escape(parts[0])
        src = (f'<br><span class="source">Source: {html.escape(parts[1])}</span>'
               if len(parts) > 1 else "")
        rationale_html = f'<div class="rationale">{body}{src}</div>'

    sf_escaped = html.escape(det.signalflow)

    return f"""
<div class="detector" id="det-{det_id}" data-threshold-type="{html.escape(det.threshold_type)}">
<div class="detector-header">
  <input type="checkbox" class="det-check" id="cb-{det_id}" data-id="{det_id}" checked>
  <label class="detector-name" for="cb-{det_id}">{html.escape(det.name)}</label>
  {badges}
</div>
<div class="signal">{html.escape(det.description)}</div>
{thresh_reason}
{rationale_html}
<span class="toggle-sf" onclick="toggleSF('{sf_id}',this)">&#9658; show SignalFlow</span>
<div class="signalflow" id="{sf_id}">{sf_escaped}</div>
</div>"""


# ── Per-service card HTML ─────────────────────────────────────────────────────

def _service_card_html(profile: ServiceProfile, detectors: list[DetectorTemplate],
                       baseline: ServiceBaseline | None) -> str:
    svc_id = re.sub(r"[^a-z0-9]+", "-", profile.service.lower()).strip("-")

    # Tech tag pills
    tech_tags = ""
    tag_color_map = {
        "jvm": "#f97316", "dotnet": "#818cf8", "nodejs": "#84cc16", "go": "#34d399",
        "python": "#f59e0b", "rust": "#fb923c", "spring_boot": "#4ade80",
        "django": "#22d3ee", "flask": "#4ade80", "fastapi": "#86efac",
        "express": "#84cc16", "grpc": "#a78bfa", "graphql": "#e879f9",
        "kafka": "#facc15", "redis": "#f87171", "kubernetes": "#60a5fa",
        "nginx": "#a3e635", "istio": "#38bdf8", "aws_rds": "#fb923c",
    }
    all_tech = profile.stacks + profile.frameworks + profile.libraries
    for t in all_tech[:6]:  # cap at 6 pills
        color = tag_color_map.get(t, "#64748b")
        tech_tags += f'<span class="tag" style="background:{color};color:#fff">{html.escape(t)}</span>'

    # Baseline line
    if baseline and baseline.is_reliable():
        err_str = f"{baseline.error_rate_pct:.2f}%" if baseline.error_rate_pct is not None else "n/a"
        bl = (f"Baseline: latency p99={baseline.latency_p99_ms:.0f}ms "
              f"error_rate={err_str} "
              f"samples={baseline.sample_count} — dynamic thresholds active")
    else:
        bl = "Baseline: insufficient data — fixed best-practice thresholds"

    detectors_html = "\n".join(_detector_html(profile.service, d) for d in detectors)

    return f"""
<div class="service-card" id="{svc_id}">
<div class="service-header">
  <input type="checkbox" class="svc-check" checked title="Select/deselect all detectors for this service">
  <span class="service-name">{html.escape(profile.service)}</span>
  <span class="service-env">{html.escape(profile.environment)}</span>
  <div class="tech-tags">{tech_tags}</div>
</div>
<div class="baseline-info">{html.escape(bl)}</div>
<div class="detectors">{detectors_html}
</div>
</div>"""


# ── Full report ───────────────────────────────────────────────────────────────

def generate_html_report(
    profiles_detectors: list[tuple[ServiceProfile, list[DetectorTemplate], ServiceBaseline | None]],
    realm: str,
    environment: str,
    generated_at: str,
    server_port: int = 7777,
    dry_run: bool = True,
) -> str:
    total_services = len(profiles_detectors)
    total_detectors = sum(len(dets) for _, dets, _ in profiles_detectors)
    total_dynamic = sum(
        sum(1 for d in dets if d.threshold_type == "dynamic")
        for _, dets, _ in profiles_detectors
    )
    total_fixed = total_detectors - total_dynamic
    mode_label = "DRY RUN" if dry_run else "LIVE"
    mode_color = "#f59e0b" if dry_run else "#22c55e"

    # TOC
    toc_items = ""
    for profile, dets, _ in profiles_detectors:
        svc_id = re.sub(r"[^a-z0-9]+", "-", profile.service.lower()).strip("-")
        toc_items += (
            f'<div class="toc-item" onclick="document.getElementById(\'{svc_id}\')'
            f'.scrollIntoView({{behavior:\'smooth\'}})">'
            f'{html.escape(profile.service)}<span class="count">{len(dets)}</span></div>\n'
        )

    # Service cards
    cards_html = "\n".join(
        _service_card_html(profile, dets, bl)
        for profile, dets, bl in profiles_detectors
    )

    js = _JS.replace("__SERVER_PORT__", str(server_port))

    deploy_btn_label = "Deploy Selected to Splunk Observability" if not dry_run else "Deploy Selected (will go live)"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Auto-Detector Provisioner Report</title>
<style>{_CSS}</style>
</head>
<body>

<div class="header">
  <h1>&#9889; Auto-Detector Provisioner Report</h1>
  <div class="meta">
    Realm: <strong>{html.escape(realm)}</strong> &nbsp;|&nbsp;
    Env: <strong>{html.escape(environment or 'all')}</strong><br>
    Generated: {html.escape(generated_at)}<br>
    Mode: <span style="color:{mode_color};font-weight:600">{mode_label}</span>
  </div>
</div>

<div class="action-bar">
  <div class="stat"><span class="n">{total_services}</span><span class="l">Services</span></div>
  <div class="stat"><span class="n">{total_detectors}</span><span class="l">Detectors</span></div>
  <div class="stat"><span class="n">{total_dynamic}</span><span class="l">Dynamic</span></div>
  <div class="stat"><span class="n">{total_fixed}</span><span class="l">Fixed</span></div>
  <div class="sep"></div>
  <input id="filter-svc" placeholder="Filter service..." oninput="applyFilters()"
         style="background:#0f172a;border:1px solid #334155;border-radius:4px;
                padding:4px 8px;font-size:12px;color:#e2e8f0;width:140px">
  <select id="filter-sev" onchange="applyFilters()"
          style="background:#0f172a;border:1px solid #334155;border-radius:4px;
                 padding:4px 8px;font-size:12px;color:#e2e8f0">
    <option value="">All severities</option>
    <option>Critical</option><option>Major</option><option>Warning</option><option>Minor</option>
  </select>
  <select id="filter-type" onchange="applyFilters()"
          style="background:#0f172a;border:1px solid #334155;border-radius:4px;
                 padding:4px 8px;font-size:12px;color:#e2e8f0">
    <option value="">All thresholds</option>
    <option value="dynamic">Dynamic</option><option value="fixed">Fixed</option>
  </select>
  <div class="sep"></div>
  <button class="btn-sm" id="btn-all">Select all</button>
  <button class="btn-sm" id="btn-none">Deselect all</button>
  <span class="sel-count" id="sel-count"></span>
  <div style="margin-left:auto">
    <button class="btn btn-deploy" id="btn-deploy" onclick="openDeployModal()">
      &#9654; {html.escape(deploy_btn_label)}
    </button>
  </div>
</div>

<nav class="toc">
{toc_items}
</nav>

<main class="main">

<div class="legend" style="margin-bottom:24px">
  <div style="display:flex;align-items:baseline;gap:12px;margin-bottom:12px">
    <h3>Badge Guide</h3>
    <span style="font-size:11px;color:#475569">severity &nbsp;&middot;&nbsp; confidence &nbsp;&middot;&nbsp; threshold type</span>
  </div>
  <div style="display:flex;gap:32px;flex-wrap:wrap">
    <div>
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#475569;margin-bottom:6px">Severity</div>
      <div style="display:flex;flex-direction:column;gap:4px;font-size:12px">
        <div><span class="badge" style="{_severity_style('Critical')}">Critical</span> &nbsp;service down or data loss imminent</div>
        <div><span class="badge" style="{_severity_style('Major')}">Major</span> &nbsp;significant degradation, users affected</div>
        <div><span class="badge" style="{_severity_style('Warning')}">Warning</span> &nbsp;early signal, investigate soon</div>
      </div>
    </div>
    <div>
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#475569;margin-bottom:6px">Confidence</div>
      <div style="display:flex;flex-direction:column;gap:4px;font-size:12px">
        <div><span class="badge" style="{_conf_style('high')[1]}">HIGH</span> &nbsp;metric confirmed, baseline sufficient</div>
        <div><span class="badge" style="{_conf_style('medium')[1]}">MED</span> &nbsp;metric exists, baseline thin or absent</div>
      </div>
    </div>
    <div>
      <div style="font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:#475569;margin-bottom:6px">Threshold</div>
      <div style="display:flex;flex-direction:column;gap:4px;font-size:12px">
        <div><span class="badge" style="{_thresh_style('dynamic')[1]}">Dynamic</span> &nbsp;learned from your traffic (mean &#177; &sigma;)</div>
        <div><span class="badge" style="{_thresh_style('fixed')[1]}">Fixed</span> &nbsp;industry defaults (SRE Book / OTel)</div>
      </div>
    </div>
  </div>
</div>

{cards_html}

</main>

<!-- Deploy modal -->
<div class="modal-overlay" id="modal-overlay" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <h2>&#9654; Deploying Selected Detectors</h2>
    <div class="deploy-log" id="deploy-log"></div>
    <div class="modal-footer">
      <button class="btn-close" id="btn-modal-close" onclick="closeModal()">Close</button>
    </div>
  </div>
</div>

<script>{js}</script>
</body>
</html>"""
