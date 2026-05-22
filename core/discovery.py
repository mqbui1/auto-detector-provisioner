"""
Service discovery — finds new environment+service combinations and detects
tech stack, frameworks, and libraries from live telemetry.
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


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
    "host":         ["cpu.utilization", "cpu.steal", "disk.io", "disk.summary", "memory.utilization", "network."],
    "aws_ec2":      ["cpu.utilization", "disk.io", "network."],
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
        "sqs":        ["aws_sqs"],
        "pubsub":     ["gcp_pubsub"],
        "activemq":   ["activemq"],
        "celery":     ["celery"],
    },
    "rpc_system": {
        "grpc":       ["grpc"],
        "dotnet_wcf": ["dotnet_wcf"],
        "java_rmi":   ["java_rmi"],
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

    def all_detected(self) -> list[str]:
        return self.stacks + self.frameworks + self.libraries


def _api_get(api_base: str, token: str, path: str, params: dict | None = None) -> dict:
    qs = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None})
    url = f"{api_base}{path}" + (f"?{qs}" if qs else "")
    req = urllib.request.Request(url, headers={"X-SF-Token": token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:300].decode()}")


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


def _list_apm_services(app_base: str, token: str, environment: str | None = None) -> list[dict]:
    """List services seen in APM within the last 24h."""
    import time
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - 24 * 3600 * 1000

    tag_filters = []
    if environment:
        tag_filters.append({"tag": "sf_environment", "operation": "IN", "values": [environment]})

    body = {
        "operationName": "GetServices",
        "variables": {
            "timeRange": {"gte": start_ms, "lte": now_ms},
            "filters": tag_filters,
        },
        "query": (
            "query GetServices($timeRange: TimeRangeInput!, $filters: [TagFilterInput!]) {"
            " services(timeRange: $timeRange, filters: $filters) {"
            " name environment } }"
        ),
    }
    try:
        result = _gql_post(app_base, token, "GetServices", body)
        return ((result.get("data") or {}).get("services") or [])
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


def _sample_spans_for_service(app_base: str, token: str, service: str, environment: str | None) -> list[dict]:
    """Sample recent spans for a service to detect span attribute fingerprints."""
    import time
    now_ms = int(time.time() * 1000)
    start_ms = now_ms - 3 * 3600 * 1000

    tag_filters = [{"tag": "service.name", "operation": "IN", "values": [service]}]
    if environment:
        tag_filters.append({"tag": "sf_environment", "operation": "IN", "values": [environment]})

    # Search for trace IDs
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
        import time as _time
        result = _gql_post(app_base, token, "StartAnalyticsSearch", start_body)
        job_id = ((result.get("data") or {}).get("startAnalyticsSearch") or {}).get("jobId")
        if not job_id:
            return []

        get_body = {
            "operationName": "GetAnalyticsSearch",
            "variables": {"jobId": job_id},
            "query": "query GetAnalyticsSearch($jobId: ID!) { getAnalyticsSearch(jobId: $jobId) }",
        }
        delay, elapsed = 0.1, 0.0
        trace_ids = []
        while elapsed < 15.0:
            r = _gql_post(app_base, token, "GetAnalyticsSearch", get_body)
            sections = ((r.get("data") or {}).get("getAnalyticsSearch") or {}).get("sections", [])
            for s in sections:
                if s.get("sectionType") == "traceExamples" and s.get("isComplete"):
                    trace_ids = [e["traceId"] for e in (s.get("legacyTraceExamples") or []) if e.get("traceId")]
                    break
            if trace_ids:
                break
            _time.sleep(delay)
            elapsed += delay
            delay = min(delay * 2, 2.0)

        # Fetch spans for first 3 traces
        spans = []
        for tid in trace_ids[:3]:
            body = {
                "operationName": "TraceFullDetailsLessValidation",
                "variables": {"id": tid},
                "query": (
                    "query TraceFullDetailsLessValidation($id: ID!) {"
                    " trace(id: $id) { spans { tags { key value } } } }"
                ),
            }
            r = _gql_post(app_base, token, "TraceFullDetailsLessValidation", body)
            spans.extend(((r.get("data") or {}).get("trace") or {}).get("spans") or [])
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

    # Check http.framework
    for fw_val in (attr_values.get("http.framework", set()) | attr_values.get("http.flavor", set())):
        for tech, values in SPAN_FINGERPRINTS["http_framework"].items():
            if any(fw_val.startswith(v) for v in values):
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
    stacks = {"jvm", "dotnet", "nodejs"}
    frameworks = {"spring_boot", "django", "flask", "fastapi", "express", "rails", "aspnetcore", "gin", "fiber"}
    libraries = {"kafka", "redis", "postgresql", "mysql", "mongodb", "rabbitmq", "celery",
                 "aws_ec2", "aws_rds", "aws_lambda", "aws_ecs", "aws_sqs", "kubernetes",
                 "grpc", "elasticsearch", "cassandra", "dynamodb", "nginx", "istio", "host"}

    for key in all_keys:
        if key in stacks:
            profile.stacks.append(key)
        elif key in frameworks:
            profile.frameworks.append(key)
        elif key in libraries:
            profile.libraries.append(key)

    return profile


def discover_services(
    realm: str,
    token: str,
    environment: str | None = None,
    known_services: set[str] | None = None,
) -> list[ServiceProfile]:
    """
    Discover services in the given environment, detect their tech stack,
    frameworks, and libraries. Optionally filter to only new services
    not in known_services.
    """
    api_base = f"https://api.{realm}.signalfx.com"
    app_base = f"https://app.{realm}.signalfx.com"

    logger.info("Discovery: listing APM services (env=%s)", environment)
    apm_services = _list_apm_services(app_base, token, environment)

    if not apm_services:
        # Fallback: discover via MTS catalog
        logger.info("Discovery: APM service list empty, falling back to MTS catalog")
        try:
            q = f'sf_environment:"{environment}"' if environment else ""
            data = _api_get(api_base, token, "/v2/metrictimeseries", {"query": q, "limit": 200})
            seen = set()
            for mts in (data.get("results") or []):
                dims = mts.get("dimensions") or {}
                svc = dims.get("sf_service") or dims.get("service.name")
                env = dims.get("sf_environment") or dims.get("deployment.environment") or environment or ""
                if svc and svc not in seen:
                    apm_services.append({"name": svc, "environment": env})
                    seen.add(svc)
        except RuntimeError as e:
            logger.warning("MTS catalog fallback failed: %s", e)

    profiles = []
    for svc_info in apm_services:
        svc_name = svc_info.get("name") or svc_info.get("service") or ""
        svc_env = svc_info.get("environment") or environment or ""

        if not svc_name:
            continue

        svc_key = f"{svc_env}/{svc_name}"
        if known_services and svc_key in known_services:
            logger.debug("Skipping known service: %s", svc_key)
            continue

        logger.info("Discovery: profiling %s (env=%s)", svc_name, svc_env)

        mts_list = _sample_mts_for_service(api_base, token, svc_name, svc_env)
        spans = _sample_spans_for_service(app_base, token, svc_name, svc_env)

        profile = _build_profile(svc_name, svc_env, mts_list, spans)
        profiles.append(profile)
        logger.info(
            "Discovery: %s → stacks=%s frameworks=%s libraries=%s",
            svc_name, profile.stacks, profile.frameworks, profile.libraries,
        )

    return profiles
