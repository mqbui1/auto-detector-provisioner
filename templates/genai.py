"""
GenAI / Agentic AI detector templates.

Covers OTel Gen AI semantic conventions (v1.27+):
  - LLM operation latency    (gen_ai.client.operation.duration)
  - LLM token usage spike    (gen_ai.client.token.usage)
  - LLM API error rate       (error.type dimension on gen_ai spans)
  - Context window saturation (input token usage approaching model limit)
  - Agent tool failure rate  (gen_ai.operation.name=execute_tool errors)
  - Response truncation      (gen_ai.response.finish_reason=length)
  - Agent root span errors   (sf_kind=SERVER — excludes intermediate tool spans)

Requires gen_ai.system span attribute to be detected (SPAN_GATED via direct_clients).
Dynamic thresholds use genai_* fields from ServiceBaseline; fall back to fixed
industry defaults until enough GenAI-specific telemetry has been observed.
"""
from __future__ import annotations

from typing import Any

from .apm import DetectorTemplate


class GenAITemplates:

    @staticmethod
    def templates(service: str, environment: str, baseline: Any | None = None) -> list[DetectorTemplate]:
        env_filter = f'filter("sf_environment", "{environment}") and ' if environment else ""
        svc_filter = f'filter("sf_service", "{service}")'
        f = f"{env_filter}{svc_filter}"

        detectors = []

        # ── LLM operation duration (p99) ──────────────────────────────────────
        # Prefer the direct gen_ai.client.operation.duration baseline (seconds)
        # over the APM latency conversion — same service but captured at the
        # LLM call level, not the HTTP endpoint level.
        genai_dur_p99 = getattr(baseline, "genai_operation_duration_p99_s", None)
        if genai_dur_p99:
            warn_s = round(genai_dur_p99, 1)
            critical_s = round(genai_dur_p99 * 1.5, 1)
            desc = (f"LLM operation p99 duration high. "
                    f"Warn: >{warn_s}s  Critical: >{critical_s}s (1.5× p99 baseline)")
            dur_threshold_type = "dynamic"
            dur_confidence = "high"
        elif baseline and baseline.latency_p99_ms:
            warn_s = round(baseline.latency_p99_ms / 1000, 1)
            critical_s = round(baseline.latency_p99_ms * 1.5 / 1000, 1)
            desc = (f"LLM operation p99 duration high. "
                    f"Warn: >{warn_s}s  Critical: >{critical_s}s (1.5× APM p99 baseline)")
            dur_threshold_type = "dynamic"
            dur_confidence = "high"
        else:
            warn_s, critical_s = 30.0, 60.0
            desc = "LLM operation p99 duration high. Warn: >30s  Critical: >60s"
            dur_threshold_type = "fixed"
            dur_confidence = "medium"

        detectors.append(DetectorTemplate(
            name=f"[{service}] LLM operation duration high",
            description=desc,
            severity="Major",
            signalflow=f"""A = data("gen_ai.client.operation.duration", filter={f}).percentile(pct=99, over="5m")
detect(when(A > {critical_s}), lasting="5m").publish("Critical")
detect(when(A > {warn_s}) and when(A <= {critical_s}), lasting="5m").publish("Warning")""",
            threshold_type=dur_threshold_type,
            confidence=dur_confidence,
            tags=["genai", "llm", "latency"],
            required_metrics=["gen_ai.client.operation.duration"],
            rationale=(
                "LLM API latency is the primary driver of agent response time. "
                "Elevated p99 indicates provider slowdowns, model overload, or excessively "
                "long prompts. Threshold: p99 warn / 1.5×p99 critical (SRE Workbook Ch.5 SLO approach)."
            ),
        ))

        # ── LLM token usage spike ─────────────────────────────────────────────
        # Sudden spike in token consumption signals a runaway agent loop,
        # recursive self-invocation, or unexpected load surge.
        # Uses trailing hourly average as a self-calibrating dynamic baseline —
        # no stored baseline needed, always adapts to current traffic level.
        detectors.append(DetectorTemplate(
            name=f"[{service}] LLM token usage rate spike",
            description=(
                "LLM token usage rate spike detected — possible runaway agent loop or load surge. "
                "Warn: >2× trailing avg  Critical: >4×"
            ),
            severity="Major",
            signalflow=f"""A = data("gen_ai.client.token.usage", filter={f}).sum(over="5m")
trailing_avg = A.mean(over="1h")
ratio = A / trailing_avg
detect(when(ratio > 4), lasting="5m").publish("Critical")
detect(when(ratio > 2) and when(ratio <= 4), lasting="5m").publish("Warning")""",
            threshold_type="dynamic",
            confidence="high",
            tags=["genai", "llm", "tokens"],
            required_metrics=["gen_ai.client.token.usage"],
            rationale=(
                "Agentic systems can enter runaway loops where each agent step spawns additional "
                "LLM calls. A token rate >2× the trailing hourly average suggests unexpected "
                "recursive behaviour or a traffic spike — both warrant investigation before "
                "cost and latency spiral."
            ),
        ))

        # ── LLM API error rate ────────────────────────────────────────────────
        # Errors on gen_ai.client.operation.duration spans (error.type dimension set).
        # Covers provider errors, rate limits, auth failures, and content filtering.
        detectors.append(DetectorTemplate(
            name=f"[{service}] LLM API error rate high",
            description=(
                "LLM API error rate high — provider errors, rate limits, or auth failures. "
                "Warn: >5%  Critical: >20%"
            ),
            severity="Critical",
            signalflow=f"""total = data("gen_ai.client.operation.duration.count", filter={f}).sum(over="5m")
errors = data("gen_ai.client.operation.duration.count", filter={f} and filter("error.type", "*")).sum(over="5m")
error_pct = (errors / total * 100).fill(0)
detect(when(error_pct > 20), lasting="3m").publish("Critical")
detect(when(error_pct > 5) and when(error_pct <= 20), lasting="5m").publish("Warning")""",
            threshold_type="fixed",
            confidence="high",
            tags=["genai", "llm", "errors"],
            required_metrics=["gen_ai.client.operation.duration"],
            rationale=(
                "The error.type dimension on gen_ai.client.operation.duration spans captures "
                "provider-side errors (HTTP 429 rate limits, 503 overload, 401 auth, content "
                "policy violations). 5% warn / 20% critical — above 20% the service is "
                "effectively degraded for users."
            ),
        ))

        # ── Context window saturation ─────────────────────────────────────────
        # When input token usage approaches the model's context limit, outputs degrade
        # (hallucinations increase, instructions are dropped) before hard truncation.
        # Dynamic: 2×/3.5× the observed baseline p95. Fixed: 50k/100k.
        ctx_baseline = getattr(baseline, "genai_input_token_p95", None)
        if ctx_baseline and ctx_baseline > 0:
            warn_tokens = int(max(ctx_baseline * 2.0, 5000))
            critical_tokens = int(max(ctx_baseline * 3.5, 10000))
            ctx_desc = (f"LLM input token p95 elevated. "
                        f"Warn: >{warn_tokens:,}  Critical: >{critical_tokens:,} "
                        f"(2× / 3.5× baseline p95={ctx_baseline:,.0f} tokens)")
            ctx_threshold_type = "dynamic"
            ctx_confidence = "high"
        else:
            warn_tokens, critical_tokens = 50000, 100000
            ctx_desc = ("LLM input token usage high — context window nearing capacity. "
                        "Warn: >50,000 tokens  Critical: >100,000 tokens")
            ctx_threshold_type = "fixed"
            ctx_confidence = "medium"

        detectors.append(DetectorTemplate(
            name=f"[{service}] LLM context window saturation",
            description=ctx_desc,
            severity="Warning",
            signalflow=f"""input_tokens = data("gen_ai.client.token.usage", filter={f} and filter("gen_ai.token.type", "input")).percentile(pct=95, over="10m")
detect(when(input_tokens > {critical_tokens}), lasting="5m").publish("Critical")
detect(when(input_tokens > {warn_tokens}) and when(input_tokens <= {critical_tokens}), lasting="5m").publish("Warning")""",
            threshold_type=ctx_threshold_type,
            confidence=ctx_confidence,
            tags=["genai", "llm", "tokens", "context"],
            required_metrics=["gen_ai.client.token.usage"],
            rationale=(
                "Models degrade silently when context fills up — instructions at the start of "
                "a long conversation get truncated (lost-in-the-middle effect) before the model "
                "returns a finish_reason=length. Dynamic thresholds at 2×/3.5× the observed "
                "baseline p95 adapt to each service's actual prompt sizes."
            ),
        ))

        # ── Agent tool failure rate ───────────────────────────────────────────
        # High failure rate on tool/function calls indicates broken integrations,
        # downstream API outages, or schema mismatches in tool definitions.
        # Dynamic: 2×/3.5× baseline rate (only when baseline < 50% — above that
        # the service is already degraded and fixed thresholds are safer).
        tool_baseline = getattr(baseline, "genai_tool_failure_rate_pct", None)
        if tool_baseline is not None and tool_baseline < 50:
            tool_warn = round(min(max(tool_baseline * 2.0, 15.0), 90.0), 1)
            tool_critical = round(min(max(tool_baseline * 3.5, 30.0), 95.0), 1)
            tool_desc = (f"Agent tool failure rate elevated. "
                         f"Warn: >{tool_warn}%  Critical: >{tool_critical}% "
                         f"(2× / 3.5× baseline {tool_baseline:.1f}%)")
            tool_threshold_type = "dynamic"
            tool_confidence = "high"
        else:
            tool_warn, tool_critical = 30.0, 60.0
            tool_desc = ("Agent tool call failure rate high — broken integrations or "
                         "downstream API issues. Warn: >30%  Critical: >60%")
            tool_threshold_type = "fixed"
            tool_confidence = "medium"

        detectors.append(DetectorTemplate(
            name=f"[{service}] Agent tool call failure rate high",
            description=tool_desc,
            severity="Major",
            signalflow=f"""tool_total = data("gen_ai.client.operation.duration.count", filter={f} and filter("gen_ai.operation.name", "execute_tool")).sum(over="5m")
tool_errors = data("gen_ai.client.operation.duration.count", filter={f} and filter("gen_ai.operation.name", "execute_tool") and filter("error.type", "*")).sum(over="5m")
tool_error_pct = (tool_errors / tool_total * 100).fill(0)
detect(when(tool_error_pct > {tool_critical}), lasting="5m").publish("Critical")
detect(when(tool_error_pct > {tool_warn}) and when(tool_error_pct <= {tool_critical}), lasting="5m").publish("Warning")""",
            threshold_type=tool_threshold_type,
            confidence=tool_confidence,
            tags=["genai", "agent", "tools", "errors"],
            required_metrics=["gen_ai.client.operation.duration"],
            rationale=(
                "Tool failures cause the agent to retry or hallucinate tool outputs, compounding "
                "errors across planning steps. Dynamic thresholds at 2×/3.5× the observed baseline "
                "rate prevent false positives on services where some tool failures are expected."
            ),
        ))

        # ── Response truncation ───────────────────────────────────────────────
        # finish_reason=length means the model hit max_tokens or the context limit.
        # Frequent truncation means outputs are incomplete — agents may loop or fail.
        # Dynamic: 2×/4× baseline rate (only when baseline < 30%).
        trunc_baseline = getattr(baseline, "genai_truncation_rate_pct", None)
        if trunc_baseline is not None and trunc_baseline < 30:
            trunc_warn = round(max(trunc_baseline * 2.0, 3.0), 1)
            trunc_critical = round(max(trunc_baseline * 4.0, 10.0), 1)
            trunc_desc = (f"LLM response truncation rate elevated. "
                          f"Warn: >{trunc_warn}%  Critical: >{trunc_critical}% "
                          f"(2× / 4× baseline {trunc_baseline:.1f}%)")
            trunc_threshold_type = "dynamic"
            trunc_confidence = "high"
        else:
            trunc_warn, trunc_critical = 10.0, 30.0
            trunc_desc = ("LLM responses truncated (finish_reason=length) — context or max_tokens "
                          "limit hit. Warn: >10%  Critical: >30%")
            trunc_threshold_type = "fixed"
            trunc_confidence = "medium"

        detectors.append(DetectorTemplate(
            name=f"[{service}] LLM response truncation rate high",
            description=trunc_desc,
            severity="Warning",
            signalflow=f"""total = data("gen_ai.client.operation.duration.count", filter={f}).sum(over="10m")
truncated = data("gen_ai.client.operation.duration.count", filter={f} and filter("gen_ai.response.finish_reason", "length")).sum(over="10m")
truncation_pct = (truncated / total * 100).fill(0)
detect(when(truncation_pct > {trunc_critical}), lasting="5m").publish("Critical")
detect(when(truncation_pct > {trunc_warn}) and when(truncation_pct <= {trunc_critical}), lasting="5m").publish("Warning")""",
            threshold_type=trunc_threshold_type,
            confidence=trunc_confidence,
            tags=["genai", "llm", "truncation"],
            required_metrics=["gen_ai.client.operation.duration"],
            rationale=(
                "finish_reason=length indicates the model ran out of output budget before completing "
                "its response. In agentic workflows this causes partial tool call JSON, broken "
                "reasoning chains, and silent task failures. Dynamic thresholds adapt to services "
                "that occasionally truncate by design."
            ),
        ))

        # ── Agent root span error rate ────────────────────────────────────────
        # Service-level error rate is inflated by expected intermediate errors
        # (tool retries, planning steps marked sf_error=true). Filtering to
        # SERVER-kind spans (user-facing invocations) gives the true failure rate.
        detectors.append(DetectorTemplate(
            name=f"[{service}] Agent invocation error rate high",
            description=(
                "Agent invocation (root SERVER span) error rate high — reflects true end-to-end "
                "agent failures, excluding intermediate tool call errors. "
                "Warn: >10%  Critical: >25%"
            ),
            severity="Critical",
            signalflow=f"""total = data("spans.count", filter={f} and filter("sf_kind", "SERVER")).sum(over="5m")
errors = data("spans.count", filter={f} and filter("sf_kind", "SERVER") and filter("sf_error", "true")).sum(over="5m")
error_pct = (errors / total * 100).fill(0)
detect(when(error_pct > 25), lasting="5m").publish("Critical")
detect(when(error_pct > 10) and when(error_pct <= 25), lasting="5m").publish("Warning")""",
            threshold_type="fixed",
            confidence="high",
            tags=["genai", "agent", "errors"],
            rationale=(
                "Agentic services routinely show 80-95% aggregate error rates because every "
                "intermediate tool call, planning step, and retry is a span — most marked "
                "sf_error=true. Filtering to sf_kind=SERVER isolates the user-facing invocations "
                "and gives an accurate signal of whether the agent is actually failing to complete "
                "tasks for users. Thresholds: 10% warn / 25% critical."
            ),
        ))

        return detectors
