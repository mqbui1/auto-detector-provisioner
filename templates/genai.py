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
        # gen_ai.client.operation.duration is in seconds (OTel standard).
        # Thresholds: p99 warn / 1.5×p99 critical (same rationale as APM latency).
        # Default 30s/60s covers typical LLM round-trip times.
        if baseline and baseline.latency_p99_ms:
            warn_s = round(baseline.latency_p99_ms / 1000, 1)
            critical_s = round(baseline.latency_p99_ms * 1.5 / 1000, 1)
            desc = (f"LLM operation p99 duration high. "
                    f"Warn: >{warn_s}s  Critical: >{critical_s}s (1.5× p99 baseline)")
            threshold_type = "dynamic"
        else:
            warn_s, critical_s = 30.0, 60.0
            desc = "LLM operation p99 duration high. Warn: >30s  Critical: >60s"
            threshold_type = "fixed"

        detectors.append(DetectorTemplate(
            name=f"[{service}] LLM operation duration high",
            description=desc,
            severity="Major",
            signalflow=f"""A = data("gen_ai.client.operation.duration", filter={f}).percentile(pct=99, over="5m")
detect(when(A > {critical_s}), lasting="5m").publish("Critical")
detect(when(A > {warn_s}) and when(A <= {critical_s}), lasting="5m").publish("Warning")""",
            threshold_type=threshold_type,
            confidence="high",
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
        # (hallucinations increase, instructions are dropped) before hard truncation occurs.
        detectors.append(DetectorTemplate(
            name=f"[{service}] LLM context window saturation",
            description=(
                "LLM input token usage high — context window nearing capacity. "
                "Warn: p95 >50k tokens  Critical: >100k tokens"
            ),
            severity="Warning",
            signalflow=f"""input_tokens = data("gen_ai.client.token.usage", filter={f} and filter("gen_ai.token.type", "input")).percentile(pct=95, over="10m")
detect(when(input_tokens > 100000), lasting="5m").publish("Critical")
detect(when(input_tokens > 50000) and when(input_tokens <= 100000), lasting="5m").publish("Warning")""",
            threshold_type="fixed",
            confidence="medium",
            tags=["genai", "llm", "tokens", "context"],
            required_metrics=["gen_ai.client.token.usage"],
            rationale=(
                "Models degrade silently when context fills up — instructions at the start of "
                "a long conversation get truncated (lost-in-the-middle effect) before the model "
                "returns a finish_reason=length. Thresholds: 50k warn covers GPT-4o-mini (128k) "
                "at ~40% fill; 100k critical applies to most frontier models."
            ),
        ))

        # ── Agent tool failure rate ───────────────────────────────────────────
        # High failure rate on tool / function calls indicates broken integrations,
        # downstream API outages, or schema mismatches in tool definitions.
        detectors.append(DetectorTemplate(
            name=f"[{service}] Agent tool call failure rate high",
            description=(
                "Agent tool call failure rate high — broken integrations or downstream API issues. "
                "Warn: >30%  Critical: >60%"
            ),
            severity="Major",
            signalflow=f"""tool_total = data("gen_ai.client.operation.duration.count", filter={f} and filter("gen_ai.operation.name", "execute_tool")).sum(over="5m")
tool_errors = data("gen_ai.client.operation.duration.count", filter={f} and filter("gen_ai.operation.name", "execute_tool") and filter("error.type", "*")).sum(over="5m")
tool_error_pct = (tool_errors / tool_total * 100).fill(0)
detect(when(tool_error_pct > 60), lasting="5m").publish("Critical")
detect(when(tool_error_pct > 30) and when(tool_error_pct <= 60), lasting="5m").publish("Warning")""",
            threshold_type="fixed",
            confidence="medium",
            tags=["genai", "agent", "tools", "errors"],
            required_metrics=["gen_ai.client.operation.duration"],
            rationale=(
                "Tool failures cause the agent to retry or hallucinate tool outputs, compounding "
                "errors across planning steps. 30% warn / 60% critical — above 60% the agent "
                "cannot reliably complete multi-step tasks."
            ),
        ))

        # ── Response truncation ───────────────────────────────────────────────
        # finish_reason=length means the model hit max_tokens or the context limit.
        # Frequent truncation means outputs are incomplete — agents may loop or fail.
        detectors.append(DetectorTemplate(
            name=f"[{service}] LLM response truncation rate high",
            description=(
                "LLM responses truncated (finish_reason=length) — context or max_tokens limit hit. "
                "Warn: >10%  Critical: >30%"
            ),
            severity="Warning",
            signalflow=f"""total = data("gen_ai.client.operation.duration.count", filter={f}).sum(over="10m")
truncated = data("gen_ai.client.operation.duration.count", filter={f} and filter("gen_ai.response.finish_reason", "length")).sum(over="10m")
truncation_pct = (truncated / total * 100).fill(0)
detect(when(truncation_pct > 30), lasting="5m").publish("Critical")
detect(when(truncation_pct > 10) and when(truncation_pct <= 30), lasting="5m").publish("Warning")""",
            threshold_type="fixed",
            confidence="medium",
            tags=["genai", "llm", "truncation"],
            required_metrics=["gen_ai.client.operation.duration"],
            rationale=(
                "finish_reason=length indicates the model ran out of output budget before completing "
                "its response. In agentic workflows this causes partial tool call JSON, broken "
                "reasoning chains, and silent task failures. 10% warn / 30% critical."
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
