"""
Service discovery — finds new environment+service combinations and detects
tech stack, frameworks, and libraries from live telemetry.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# Synthetic/load-test service names — skip entirely, no detectors needed
_SYNTHETIC_NAMES = frozenset({
    "load-generator", "load_generator", "loadgenerator",
    "locust", "k6", "gatling", "jmeter", "synthetic",
})

# ── Stack / framework / library fingerprints ──────────────────────────────────

# Metric name prefixes that indicate a specific stack/library
METRIC_FINGERPRINTS: dict[str, list[str]] = {
    "jvm":          ["jvm.", "process.runtime.jvm.", "java."],
    "dotnet":       ["process.runtime.dotnet.", "dotnet."],
    "nodejs":       ["process.runtime.nodejs.", "nodejs."],
    "spring_boot":  ["spring.", "tomcat.", "hikaricp."],
    "kafka":        ["kafka.consumer.", "kafka.producer.", "kafka."],
    "redis":        ["redis.", "lettuce.", "jedis."],
    "postgresql":   ["postgresql.", "pg."],
    "mysql":        ["mysql."],
    "mongodb":      ["mongodb."],
    "rabbitmq":     ["rabbitmq."],
    "celery":       ["celery."],
    "elasticsearch": ["elasticsearch."],
    "cassandra":    ["cassandra."],
    "nginx":        ["nginx."],
    "istio":        ["istio_", "envoy_"],
    "aws_rds":      ["aws.rds."],
    "aws_lambda":   ["aws.lambda."],
    "aws_ecs":      ["aws.ecs."],
    "aws_sqs":      ["aws.sqs."],
    "kubernetes":   ["k8s.", "container."],
}

# Span attribute values that indicate a specific library
SPAN_FINGERPRINTS: dict[str, dict[str, list[str]]] = {
    "db_system": {
        "postgresql": ["postgresql"],
        "mysql":      ["mysql"],
        "mongodb":    ["mongodb"],
        "redis":      ["redis"],
        "elasticsearch": ["elasticsearch"],
        "cassandra":  ["cassandra"],
        "dynamodb":   ["dynamodb"],
        "mssql":      ["mssql", "microsoft_sql_server"],
    },
    "messaging_system": {
        "kafka":      ["kafka"],
        "rabbitmq":   ["rabbitmq"],
        "aws_sqs":    ["aws_sqs"],
        "pubsub":     ["gcp_pubsub"],
        "activemq":   ["activemq"],
        "celery":     ["celery"],
    },
    "rpc_system": {
        "grpc":       ["grpc"],
        "dotnet_wcf": ["dotnet_wcf"],
        "java_rmi":   ["java_rmi"],
    },
    # OTel Gen AI semantic conventions — any gen_ai.system value means LLM/agentic service
    "gen_ai_system": {
        "genai": ["openai", "anthropic", "cohere", "vertex_ai", "bedrock", "mistral",
                  "ollama", "hugging_face", "azure", "grok", "deepseek", "groq"],
    },
    "http_framework": {
        "spring":     ["spring", "spring_boot", "spring-webmvc"],
        "django":     ["django"],
        "flask":      ["flask"],
        "fastapi":    ["fastapi"],
        "express":    ["express"],
        "rails":      ["rails", "action_pack"],
        "aspnetcore": ["asp.net_core", "microsoft.aspnetcore"],
        "gin":        ["gin"],
        "fiber":      ["fiber"],
    },
    # otel.scope.name fingerprints — reliable language/framework detection
    # even when no runtime metrics are emitted (Go, Rust, Python, Next.js, etc.)
    "otel_scope": {
        "nodejs":      ["@opentelemetry/instrumentation", "next.js", "opentelemetry-instrumentation-express",
                        "opentelemetry-instrumentation-fastify", "opentelemetry-instrumentation-koa"],
        "dotnet":      ["microsoft.aspnetcore", "microsoft.entityframeworkcore",
                        "system.net.http", "azure.",
                        "opentelemetry.instrumentation.aspnetcore",
                        "opentelemetry.instrumentation.grpcnetclient",
                        "opentelemetry.instrumentation.sqlclient",
                        "opentelemetry.instrumentation.stackexchangeredis",
                        "opentelemetry.instrumentation.entityframeworkcore"],
        "jvm":         ["io.opentelemetry.spring", "io.opentelemetry.tomcat",
                        "io.opentelemetry.netty", "io.opentelemetry.jdbc"],
        "go":          ["go.opentelemetry.io", "github.com/", "google.golang.org"],
        "python":      ["opentelemetry.instrumentation.", "opentelemetry-instrumentation-flask",
                        "opentelemetry-instrumentation-django", "opentelemetry-instrumentation-fastapi",
                        "opentelemetry-instrumentation-requests", "opentelemetry-instrumentation-grpc",
                        "opentelemetry-instrumentation-sqlalchemy", "opentelemetry-instrumentation-celery",
                        "opentelemetry-instrumentation-redis", "opentelemetry-instrumentation-pymongo",
                        "opentelemetry-instrumentation-psycopg2", "opentelemetry-instrumentation-boto",
                        "opentelemetry-instrumentation-aiohttp", "opentelemetry-instrumentation-starlette"],
        "rust":        ["opentelemetry-instrumentation-actix", "opentelemetry-instrumentation-rocket",
                        "opentelemetry-instrumentation-axum"],
        "grpc":        ["@opentelemetry/instrumentation-grpc",
                        "go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc"],
        "express":     ["@opentelemetry/instrumentation-express"],
        "fastapi":     ["opentelemetry-instrumentation-fastapi"],
        "django":      ["opentelemetry-instrumentation-django"],
        "flask":       ["opentelemetry-instrumentation-flask"],
        "aspnetcore":  ["microsoft.aspnetcore"],
        "nextjs":      ["next.js"],
        "istio":       ["envoy"],
    },
    # telemetry.sdk.language — explicit language tag from OTel SDK
    "sdk_language": {
        "go":     ["go"],
        "python": ["python"],
        "nodejs": ["nodejs", "javascript"],
        "dotnet": ["dotnet"],
        "jvm":    ["java"],
        "rust":   ["rust"],
        "cpp":    ["cpp"],
        "ruby":   ["ruby"],
    },
}


@dataclass
class ServiceProfile:
    service: str
    environment: str
    # Detected capabilities
    stacks: list[str] = field(default_factory=list)       # jvm, dotnet, nodejs
    frameworks: list[str] = field(default_factory=list)   # spring_boot, django, etc.
    libraries: list[str] = field(default_factory=list)    # kafka, redis, postgresql, etc.
    # Raw signals
    metric_names: list[str] = field(default_factory=list)
    span_attributes: dict[str, set[str]] = field(default_factory=dict)
    # Confidence: high/medium/low per detection
    confidence: dict[str, str] = field(default_factory=dict)
    # Libraries confirmed via direct span evidence (db.system, messaging.system, etc.)
    # Only these get library-specific detector templates
    direct_clients: set[str] = field(default_factory=set)
    # Criticality: number of unique upstream callers seen in span samples
    fan_in_count: int = 0
    is_critical_path: bool = False  # True when fan_in_count >= 3

    def all_detected(self) -> list[str]:
        return self.stacks + self.frameworks + self.libraries


def _api_get(api_base: str, token: str, path: str, params: dict | None = None) -> dict:
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
    except Exception as e:
        raise RuntimeError(f"Request failed: {e}")


def _gql_post(app_base: str, token: str, op: str, body: dict) -> dict:
    url = f"{app_base}/v2/apm/graphql?op={op}"
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
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:300].decode()}")


def _list_apm_services(app_base: str, token: str, environment: str | None = None, window_hours: int = 24) -> list[dict]:
    """List services seen in APM within the given lookback window."""
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - window_hours * 3600 * 1000

    tag_filters = []
    if environment:
        tag_filters.append({"tag": "sf_environment", "operation": "IN", "values": [environment]})

    # Try newer APM service endpoint first
    env_filter_str = f'filter("sf_environment", "{environment}")' if environment else "true"
    body = {
        "operationName": "GetServices",
        "variables": {
            "timeRange": {"gte": start_ms, "lte": now_ms},
            "environmentFilter": environment or "",
        },
        "query": (
            "query GetServices($environmentFilter: String) {"
            " serviceNames(environmentName: $environmentFilter) }"
        ),
    }
    try:
        result = _gql_post(app_base, token, "GetServices", body)
        names = ((result.get("data") or {}).get("serviceNames") or [])
        if names:
            env_val = environment or ""
            return [{"name": n, "environment": env_val} for n in names if n]
        return []
    except RuntimeError as e:
        logger.warning("APM service list failed: %s", e)
        return []


def _sample_mts_for_service(api_base: str, token: str, service: str, environment: str | None) -> list[dict]:
    """Sample MTS for a service to detect metric-based fingerprints."""
    filters = [f'sf_service:"{service}"']
    if environment:
        filters.append(f'sf_environment:"{environment}"')
    try:
        data = _api_get(api_base, token, "/v2/metrictimeseries", {
            "query": " AND ".join(filters), "limit": 200,
        })
        return data.get("results") or []
    except RuntimeError as e:
        logger.warning("MTS sample failed for %s: %s", service, e)
        return []


def _sample_spans_for_service(app_base: str, token: str, service: str, environment: str | None, window_hours: int = 24) -> list[dict]:
    """Sample recent spans for a service to detect span attribute fingerprints."""
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - window_hours * 3600 * 1000

    # Use sf_service (Splunk APM dimension) not service.name (OTel attribute)
    tag_filters = [{"tag": "sf_service", "operation": "IN", "values": [service]}]
    if environment:
        tag_filters.append({"tag": "sf_environment", "operation": "IN", "values": [environment]})

    # Search for trace IDs via analytics search
    params = {
        "sharedParameters": {
            "timeRangeMillis": {"gte": start_ms, "lte": now_ms},
            "filters": [{"traceFilter": {"tags": tag_filters}, "filterType": "traceFilter"}],
            "samplingFactor": 100,
        },
        "sectionsParameters": [{"sectionType": "traceExamples", "limit": 5}],
    }
    start_body = {
        "operationName": "StartAnalyticsSearch",
        "variables": {"parameters": params},
        "query": "query StartAnalyticsSearch($parameters: JSON!) { startAnalyticsSearch(parameters: $parameters) }",
    }
    try:
        result = _gql_post(app_base, token, "StartAnalyticsSearch", start_body)
        job_id = ((result.get("data") or {}).get("startAnalyticsSearch") or {}).get("jobId")
        if not job_id:
            return []

        get_body = {
            "operationName": "GetAnalyticsSearch",
            "variables": {"jobId": job_id},
            "query": "query GetAnalyticsSearch($jobId: ID!) { getAnalyticsSearch(jobId: $jobId) }",
        }
        delay, elapsed = 0.5, 0.0
        trace_ids = []
        while elapsed < 10.0:
            r = _gql_post(app_base, token, "GetAnalyticsSearch", get_body)
            sections = ((r.get("data") or {}).get("getAnalyticsSearch") or {}).get("sections", [])
            for s in sections:
                if s.get("sectionType") == "traceExamples" and s.get("isComplete"):
                    trace_ids = [e["traceId"] for e in (s.get("legacyTraceExamples") or []) if e.get("traceId")]
                    break
            if trace_ids:
                break
            time.sleep(delay)
            elapsed += delay
            delay = min(delay * 2, 2.0)

        if not trace_ids:
            logger.debug("Span sample: no traces found for %s", service)
            return []

        # Fetch spans for first 3 traces, filtering to target service only
        spans = []
        for tid in trace_ids[:3]:
            body = {
                "operationName": "TraceFullDetailsLessValidation",
                "variables": {"id": tid},
                "query": (
                    "query TraceFullDetailsLessValidation($id: ID!) {"
                    " trace(id: $id) { spans { serviceName tags { key value } } } }"
                ),
            }
            r = _gql_post(app_base, token, "TraceFullDetailsLessValidation", body)
            all_spans = ((r.get("data") or {}).get("trace") or {}).get("spans") or []
            # Only include spans from the target service
            spans.extend(s for s in all_spans if s.get("serviceName") == service)
        return spans
    except RuntimeError as e:
        logger.warning("Span sample failed for %s: %s", service, e)
        return []


def _detect_stack_from_metrics(metric_names: list[str]) -> dict[str, str]:
    """Returns {technology: confidence} from metric names."""
    detected = {}
    mn_lower = [m.lower() for m in metric_names]

    for tech, prefixes in METRIC_FINGERPRINTS.items():
        matches = sum(1 for m in mn_lower for p in prefixes if m.startswith(p))
        if matches >= 3:
            detected[tech] = "high"
        elif matches >= 1:
            detected[tech] = "medium"

    return detected


def _detect_stack_from_spans(spans: list[dict]) -> dict[str, str]:
    """Returns {technology: confidence} from span attributes."""
    detected = {}
    attr_values: dict[str, set[str]] = {}

    for span in spans:
        for tag in (span.get("tags") or []):
            k = str(tag.get("key") or "").lower()
            v = str(tag.get("value") or "").lower()
            attr_values.setdefault(k, set()).add(v)

    # Check db.system
    for db_val in attr_values.get("db.system", set()):
        for tech, values in SPAN_FINGERPRINTS["db_system"].items():
            if any(db_val.startswith(v) for v in values):
                detected[tech] = "high"

    # Check messaging.system
    for msg_val in attr_values.get("messaging.system", set()):
        for tech, values in SPAN_FINGERPRINTS["messaging_system"].items():
            if any(msg_val.startswith(v) for v in values):
                detected[tech] = "high"

    # Check rpc.system
    for rpc_val in attr_values.get("rpc.system", set()):
        for tech, values in SPAN_FINGERPRINTS["rpc_system"].items():
            if any(rpc_val.startswith(v) for v in values):
                detected[tech] = "high"

    # Check gen_ai.system — OTel Gen AI semantic conventions
    for ai_val in attr_values.get("gen_ai.system", set()):
        matched = False
        for tech, values in SPAN_FINGERPRINTS["gen_ai_system"].items():
            if any(ai_val.startswith(v) for v in values):
                detected[tech] = "high"
                matched = True
        if not matched:
            # Unknown provider but gen_ai.system is set → still an AI service
            detected["genai"] = "high"

    # Check http.framework
    for fw_val in (attr_values.get("http.framework", set()) | attr_values.get("http.flavor", set())):
        for tech, values in SPAN_FINGERPRINTS["http_framework"].items():
            if any(fw_val.startswith(v) for v in values):
                detected[tech] = "high"

    # Check otel.scope.name — most reliable for Go/Rust/Python/Next.js
    # which don't emit runtime metrics but have distinctive scope names.
    # Collect all scope matches first, then apply: more-specific techs win over generic ones.
    scope_matches: dict[str, int] = {}  # tech → match count
    for scope_val in attr_values.get("otel.scope.name", set()):
        for tech, prefixes in SPAN_FINGERPRINTS["otel_scope"].items():
            if any(scope_val.startswith(p.lower()) for p in prefixes):
                scope_matches[tech] = scope_matches.get(tech, 0) + 1

    # Apply scope matches with language exclusivity.
    # Priority: rust/dotnet/jvm > go > nodejs > python (generic prefix)
    # Once a primary language stack is confirmed, don't add conflicting stacks.
    primary_stacks = {"rust", "dotnet", "jvm", "go", "nodejs", "python"}
    priority_order = ["rust", "dotnet", "jvm", "aspnetcore", "go", "nodejs", "nextjs",
                      "express", "fastapi", "django", "flask", "grpc", "istio", "python"]
    for tech in priority_order:
        if tech not in scope_matches:
            continue
        # Skip python if a more-specific primary language was already confirmed
        if tech == "python" and any(s in detected for s in primary_stacks - {"python"}):
            continue
        if tech not in detected:
            detected[tech] = "high"
    # Add any remaining matches not in priority list (frameworks/libs)
    for tech in scope_matches:
        if tech not in detected and tech not in primary_stacks:
            detected[tech] = "high"

    # Check telemetry.sdk.language — explicit OTel SDK language tag
    for lang_val in attr_values.get("telemetry.sdk.language", set()):
        for tech, values in SPAN_FINGERPRINTS["sdk_language"].items():
            if lang_val in values:
                if tech not in detected:
                    detected[tech] = "high"

    return detected


def _build_profile(
    service: str,
    environment: str,
    mts_list: list[dict],
    spans: list[dict],
) -> ServiceProfile:
    profile = ServiceProfile(service=service, environment=environment)

    # Collect metric names
    metric_names = list({
        str(mts.get("metric") or mts.get("name") or "")
        for mts in mts_list
        if mts.get("metric") or mts.get("name")
    })
    profile.metric_names = metric_names

    # Detect from metrics
    metric_detected = _detect_stack_from_metrics(metric_names)

    # Detect from spans
    span_detected = _detect_stack_from_spans(spans)

    # Merge — metric + span agreement → high confidence
    all_keys = set(metric_detected) | set(span_detected)
    for key in all_keys:
        mc = metric_detected.get(key)
        sc = span_detected.get(key)
        if mc and sc:
            profile.confidence[key] = "high"
        elif mc == "high" or sc == "high":
            profile.confidence[key] = "high"
        else:
            profile.confidence[key] = "medium"

    # Classify into stacks / frameworks / libraries
    stacks = {"jvm", "dotnet", "nodejs", "go", "python", "rust", "ruby", "cpp"}
    frameworks = {"spring_boot", "django", "flask", "fastapi", "express", "rails",
                  "aspnetcore", "gin", "fiber", "grpc", "graphql", "nextjs"}
    libraries = {"kafka", "redis", "postgresql", "mysql", "mongodb", "rabbitmq", "celery",
                 "aws_rds", "aws_lambda", "aws_ecs", "aws_sqs", "kubernetes",
                 "elasticsearch", "cassandra", "dynamodb", "nginx", "istio", "genai"}

    for key in all_keys:
        if key in stacks:
            profile.stacks.append(key)
        elif key in frameworks:
            profile.frameworks.append(key)
        elif key in libraries:
            profile.libraries.append(key)

    # direct_clients: only libraries confirmed by span evidence (db.system, messaging.system)
    # These are the only ones that get library-specific detector templates applied.
    # Metric-only detections (e.g. a shared Redis metric on the host) are excluded.
    db_libs = {"kafka", "redis", "postgresql", "mysql", "mongodb", "rabbitmq",
               "elasticsearch", "cassandra", "dynamodb", "mssql", "genai"}
    profile.direct_clients = {k for k in span_detected if k in db_libs}

    # Criticality: count unique upstream callers from server-side spans.
    # A span.kind=server span with a peer.service tag means another service called us.
    upstream_callers: set[str] = set()
    for span in spans:
        tags = span.get("tags") or []
        is_server = any(
            t.get("key") == "span.kind" and t.get("value") in ("server", "consumer")
            for t in tags
        )
        if is_server:
            peer = next((t.get("value") for t in tags if t.get("key") == "peer.service"), None)
            if peer and peer != service:
                upstream_callers.add(peer)
    profile.fan_in_count = len(upstream_callers)
    profile.is_critical_path = profile.fan_in_count >= 3

    return profile


def discover_services(
    realm: str,
    token: str,
    environment: str | None = None,
    known_services: set[str] | None = None,
    window_hours: int = 168,
) -> list[ServiceProfile]:
    """
    Discover services in the given environment, detect their tech stack,
    frameworks, and libraries. Optionally filter to only new services
    not in known_services.
    """
    api_base = f"https://api.{realm}.signalfx.com"
    app_base = f"https://app.{realm}.signalfx.com"

    logger.info("Discovery: listing APM services (env=%s, window=%dh)", environment, window_hours)
    apm_services = _list_apm_services(app_base, token, environment, window_hours=window_hours)

    # Always supplement APM discovery with MTS catalog so we catch services
    # that emit OTel metrics (service.name dimension) but no APM spans —
    # e.g. batch jobs, infrastructure exporters, sidecars, metric-only services.
    seen: set[str] = set(s.get("name", "") for s in apm_services)
    logger.info("Discovery: supplementing with MTS catalog (env=%s)", environment)

    # APM-promoted metrics use sf_service; OTel SDK metrics use service.name
    mts_queries: list[tuple[str, str]] = [
        ("service.request.count", "sf_service"),
        ("spans.count", "sf_service"),
        ("process.runtime.go.goroutines", "service.name"),
        ("process.runtime.jvm.memory.used", "service.name"),
        ("process.runtime.nodejs.memory.heap.used", "service.name"),
        ("process.runtime.dotnet.gc.heap.size", "service.name"),
    ]
    for metric, svc_dim in mts_queries:
        try:
            parts = [f'sf_metric:"{metric}"']
            if environment:
                env_dim = "sf_environment" if svc_dim == "sf_service" else "deployment.environment"
                parts.append(f'{env_dim}:"{environment}"')
            data = _api_get(api_base, token, "/v2/metrictimeseries", {"query": " AND ".join(parts), "limit": 1000})
            for mts in (data.get("results") or []):
                dims = mts.get("dimensions") or {}
                svc = dims.get(svc_dim) or dims.get("sf_service") or dims.get("service.name")
                env = (dims.get("sf_environment") or dims.get("deployment.environment")
                       or environment or "")
                if svc and svc not in seen:
                    apm_services.append({"name": svc, "environment": env})
                    seen.add(svc)
        except RuntimeError as e:
            logger.warning("Discovery: MTS probe failed for metric %s: %s", metric, e)

    if not apm_services:
        logger.warning("Discovery: no services found via APM catalog or MTS probe")

    profiles = []
    for svc_info in apm_services:
        svc_name = svc_info.get("name") or svc_info.get("service") or ""
        svc_env = svc_info.get("environment") or environment or ""

        if not svc_name:
            continue

        svc_lower = svc_name.lower()
        if svc_lower in _SYNTHETIC_NAMES or any(
            svc_lower.startswith(p + "-") or svc_lower.startswith(p + "_")
            for p in _SYNTHETIC_NAMES
        ):
            logger.info("Discovery: skipping synthetic service: %s", svc_name)
            continue

        svc_key = f"{svc_env}/{svc_name}"
        if known_services and svc_key in known_services:
            logger.debug("Skipping known service: %s", svc_key)
            continue

        logger.info("Discovery: profiling %s (env=%s)", svc_name, svc_env)

        mts_list = _sample_mts_for_service(api_base, token, svc_name, svc_env)
        # Cap span sampling at 24h — recent spans are representative for fingerprinting
        span_window = min(window_hours, 24)
        spans = _sample_spans_for_service(app_base, token, svc_name, svc_env, window_hours=span_window)

        profile = _build_profile(svc_name, svc_env, mts_list, spans)
        profiles.append(profile)
        logger.info(
            "Discovery: %s → stacks=%s frameworks=%s libraries=%s",
            svc_name, profile.stacks, profile.frameworks, profile.libraries,
        )

    return profiles
