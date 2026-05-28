# Auto-Detector Provisioner

Automatically discovers services in Splunk Observability Cloud, detects their tech stack, frameworks, and libraries from live telemetry, learns behavioral baselines, and provisions best-practice detectors tuned to the application's actual behavior.

## How it works

1. **Discovery** — queries APM and MTS catalog to find all services in an environment
2. **Stack detection** — infers tech stack (JVM, .NET, Node.js), frameworks (Spring Boot, Django, Express), and libraries (Kafka, Redis, PostgreSQL, gRPC) from metric names and span attributes
3. **Baseline learning** — observes the service over a configurable window (default 24h) to compute mean, stddev, and percentile thresholds for latency and error rate
4. **Detector generation** — matches detected technologies to best-practice detector templates, parameterized with observed baselines where available
5. **Deployment** — dry-run by default; use `--auto-deploy` to push detectors to Splunk Observability

## Detector types

| Category | Coverage |
|---|---|
| **APM** | Latency anomaly, error rate, request rate drop, silent service |
| **JVM** | Heap %, GC pause, GC rate, thread count, metaspace, Hikari pool, Tomcat threads |
| **.NET** | GC collections, heap size, exception rate, thread pool queue |
| **Node.js** | Heap %, event loop lag, active handles |
| **Go** | Goroutine count, GC pause, heap allocation rate, heap in-use |
| **Python** | Thread count, GC collection rate, RSS memory, CPU utilization |
| **Rust** | HTTP 5xx rate, request latency, panic/internal error rate |
| **Spring Boot** | HTTP 5xx rate, request latency, actuator health, scheduler failures, outbound client errors |
| **Django** | HTTP 5xx rate, request latency, ORM slow queries, template render time, DB connection errors |
| **Flask** | HTTP 5xx rate, request latency, unhandled exceptions, active request concurrency |
| **FastAPI** | HTTP 5xx rate, request latency, 422 validation errors, background task failures |
| **Express** | HTTP 5xx rate, request latency, unhandled promise rejections, middleware timeouts, active connections |
| **gRPC** | RPC error rate, server latency, deadline exceeded, UNAVAILABLE errors, client cancellations, client error rate |
| **GraphQL** | Resolver error rate, query latency, mutation error rate, query depth/complexity abuse, N+1 pattern |
| **Kafka** | Consumer lag, lag growth, rebalance rate, producer errors, DLQ depth |
| **RabbitMQ** | Queue depth, unacked messages, consumer count drop, memory/disk alarms, channel errors |
| **Celery** | Task failure rate, queue depth, worker count, execution duration, retry rate, timeouts |
| **Redis** | Cache hit rate, eviction rate, connection count, latency, memory % |
| **Database** | Query latency, connection pool saturation, deadlocks, N+1 detection |
| **Elasticsearch** | Cluster health, unassigned shards, JVM heap, search/index latency, thread pool rejections |
| **Cassandra** | Read/write latency, dropped mutations, compaction backlog, JVM heap, hinted handoff |
| **Kubernetes** | Pod restarts, OOMKilled, CPU throttling, HPA at max, pending pods, desired vs running |
| **Nginx** | Upstream 5xx rate, worker saturation, upstream latency, request rate drop, 4xx spike |
| **Istio/Envoy** | Sidecar error rate, circuit breaker open, upstream cx failures, mTLS failures, retry budget |
| **Host/Linux** | CPU utilization, CPU steal, memory pressure, disk I/O saturation, network loss, file descriptors |
| **AWS** | Lambda errors/throttles/cold starts, RDS connections/replica lag, SQS age/DLQ, ECS task count |
| **HTTP patterns** | 429 rate limiting, 401/403 auth failures, 502/503/504 gateway errors (all HTTP services) |
| **Batch/Cron** | Job failures, duration anomaly, missed schedule |
| **Observability** | OTel span export errors, metric reporting gaps, sampler drop rate |

## Baseline learning

Baselines are computed by running SignalFlow queries against the last 24 hours of live telemetry (configurable via `--baseline-window-hours`).

### Latency baseline

Tries these metrics in order, uses the first one with data:

1. `service.request.duration` — OTel standard (seconds)
2. `service.request.duration.ns.median` — Splunk APM (nanoseconds)
3. `spans.duration.ns.median` — Splunk APM spans metric

From 1-minute resolution data points over the window, it computes **mean**, **stddev**, and **p50/p95/p99** percentiles.

### Error rate baseline

```
error_count / total_count × 100
```

Where `error_count` filters on `sf_error=true` spans over the same window.

### Threshold derivation

| Threshold | Formula |
|-----------|---------|
| Warn | `mean + 2 × stddev` |
| Anomaly / Critical | `mean + 3 × stddev` |

For example, a service with mean latency 247ms and stddev 100ms gets: warn at 447ms, anomaly at 547ms.

### Dynamic vs Fixed

A baseline is **reliable** when `sample_count ≥ 30`. If there aren't enough samples (new service, low-traffic service), thresholds fall back to fixed industry defaults:

| Signal | Fixed warn | Fixed critical |
|--------|-----------|----------------|
| Latency | 1 000ms | 3 000ms |
| Error rate | 1% | 5% |

### Cache behavior

Baselines are cached in `data/baselines/<env>__<service>.json` and automatically invalidated when:
- Older than **7 days**
- `sample_count < 100` (indicates a broken or empty learning run)

Use `--skip-baseline` to force fixed thresholds, or delete the cache file to force a re-learn on the next run.

## Threshold types

- **Dynamic** (📈) — thresholds derived from observed baseline (`mean + N×stddev`). Requires sufficient samples.
- **Fixed** (📏) — community best-practice thresholds (e.g. JVM heap >75% warn, >90% critical)
- **Hybrid** (🔀) — fixed floor threshold with dynamic upper bound (e.g. Kafka lag)

## Confidence levels

- **High** (✓) — technology confirmed via multiple independent signals
- **Medium** (~) — technology inferred from a single signal
- **Low** (?) — heuristic guess; excluded from auto-deploy by default

## Installation

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your realm and token
```

## Usage

```bash
# Dry run — show all detectors that would be created
python3 provision.py --realm us1 --token $TOKEN --environment production

# Scope to a specific service
python3 provision.py --realm us1 --token $TOKEN --environment production --service payment-service

# Auto-deploy detectors
python3 provision.py --realm us1 --token $TOKEN --environment production --auto-deploy

# Reconcile — update changed detectors in-place, create missing ones, skip unchanged
python3 provision.py --realm us1 --token $TOKEN --environment production --reconcile --auto-deploy

# Use fixed thresholds only (skip baseline learning)
python3 provision.py --realm us1 --token $TOKEN --environment production --skip-baseline

# Include low-confidence (heuristic) detectors
python3 provision.py --realm us1 --token $TOKEN --environment production --include-low-confidence

# Use a shorter baseline window
python3 provision.py --realm us1 --token $TOKEN --environment production --baseline-window-hours 6
```

## Lifecycle management

```bash
# Retune thresholds based on updated baseline (dry-run)
python3 provision.py --realm us1 --token $TOKEN --environment production --retune

# Retune and apply changes
python3 provision.py --realm us1 --token $TOKEN --environment production --retune --auto-deploy

# Mute a service during a 30-minute deployment window
python3 provision.py --realm us1 --token $TOKEN --environment production --service payment-service --mute 30

# Unmute a service
python3 provision.py --realm us1 --token $TOKEN --environment production --service payment-service --unmute

# List all active muting rules
python3 provision.py --realm us1 --token $TOKEN --environment production --list-mutes

# Archive a decommissioned service (dry-run — shows what would be deleted)
python3 provision.py --realm us1 --token $TOKEN --environment production --service old-service --archive

# Archive and delete detectors
python3 provision.py --realm us1 --token $TOKEN --environment production --service old-service --archive --auto-deploy

# Scan for stale services (not seen in 7 days) and archive them
python3 provision.py --realm us1 --token $TOKEN --environment production --archive-stale --auto-deploy

# Continuous watch mode — auto-provision new services, retune on drift
python3 provision.py --realm us1 --token $TOKEN --environment production --watch --poll-interval 60

# Watch mode with auto-archival of stale services
python3 provision.py --realm us1 --token $TOKEN --environment production --watch --auto-archive --auto-deploy
```

## Example output

```
======================================================================
SERVICE: payment-service  ENV: production
======================================================================

DETECTED TECHNOLOGIES:
  Stacks:     jvm
  Frameworks: spring_boot
  Libraries:  postgresql, kafka, redis

LEARNED BASELINE:
  Latency mean:   142.3ms
  Latency p99:    380.1ms
  Latency stddev: 28.4ms
  Error rate:     0.12%
  Sample count:   1847

DETECTORS TO CREATE (18):
----------------------------------------------------------------------

  [APM]
    ✓ 📈 [Major] [payment-service] Latency anomaly (p99)
       Warn: >199.1ms  Anomaly: >227.5ms
    ✓ 📈 [Major] [payment-service] Error rate anomaly
       Warn: >0.24%  Anomaly: >0.48%
    ✓ 📏 [Critical] [payment-service] Service stopped emitting spans

  [JVM]
    ✓ 📏 [Major] [payment-service] JVM heap usage high
    ✓ 📏 [Major] [payment-service] JVM GC pause time high
    ✓ 📏 [Major] [payment-service] JVM thread count high
    ~ 📏 [Major] [payment-service] Hikari connection pool exhaustion
    ~ 📏 [Major] [payment-service] Tomcat thread pool exhaustion

  [KAFKA]
    ✓ 🔀 [Major] [payment-service] Kafka consumer lag high
    ✓ 📏 [Warning] [payment-service] Kafka consumer lag growing
    ✓ 📏 [Major] [payment-service] Kafka producer error rate

  [POSTGRESQL]
    ✓ 📏 [Major] [payment-service] PostgreSQL connection pool saturation
    ✓ 📏 [Major] [payment-service] PostgreSQL deadlocks detected

  [REDIS]
    ✓ 📏 [Warning] [payment-service] Redis cache hit rate low
    ✓ 📏 [Major] [payment-service] Redis eviction rate high

LEGEND:
  Confidence: ✓ high  ~ medium  ? low
  Threshold:  📈 dynamic (baseline-tuned)  📏 fixed (best practice)  🔀 hybrid

DRY RUN SUMMARY: 18/18 detectors would be created

Run with --auto-deploy to create these detectors.
```

## Architecture

```
provision.py (CLI entry point)
    │
    ├── core/discovery.py          — service discovery + stack/library detection
    ├── core/baseline_learner.py   — SignalFlow-based baseline computation
    ├── core/detector_generator.py — template matching + dry-run report
    ├── core/detector_deployer.py  — Splunk Observability API deployment
    ├── core/state.py              — provisioned state tracking (idempotent reruns)
    ├── core/retune.py             — baseline drift detection + threshold updates
    ├── core/mute.py               — muting rules (deploy windows, maintenance)
    ├── core/archive.py            — stale service detection + detector cleanup
    ├── core/watch.py              — continuous provisioning daemon
    ├── core/html_report.py        — interactive HTML report generation
    └── core/report_server.py      — local deploy server for HTML report

tests/
    └── test_templates.py  — validates every template against the live Splunk API

templates/
    ├── apm.py        — latency, error rate, availability (all services)
    ├── jvm.py        — JVM heap, GC, threads, Hikari pool, Tomcat
    ├── dotnet.py     — .NET GC, heap, exceptions, thread pool
    ├── nodejs.py     — Node.js heap, event loop lag, active handles
    ├── spring_boot.py — HTTP 5xx, request latency, actuator health, scheduler
    ├── django.py     — HTTP 5xx, request latency, ORM queries, DB connections
    ├── flask.py      — HTTP 5xx, request latency, unhandled exceptions
    ├── fastapi.py    — HTTP 5xx, latency, 422 validation errors, background tasks
    ├── express.py    — HTTP 5xx, latency, promise rejections, middleware timeouts
    ├── grpc.py       — RPC error rate, latency, deadline exceeded, UNAVAILABLE
    ├── graphql.py    — resolver errors, query latency, mutations, N+1, complexity
    ├── kafka.py          — consumer lag, producer errors, DLQ
    ├── rabbitmq.py       — queue depth, unacked, consumer drop, alarms
    ├── celery.py         — task failures, queue depth, worker count, duration
    ├── redis.py          — hit rate, evictions, connections, latency
    ├── database.py       — PostgreSQL, MySQL, MongoDB, N+1 detection
    ├── elasticsearch.py  — cluster health, shards, JVM heap, latency, rejections
    ├── cassandra.py      — read/write latency, compaction, dropped mutations
    ├── kubernetes.py     — pod restarts, OOMKilled, HPA, CPU throttling
    ├── nginx.py          — upstream errors, worker saturation, latency, request drop
    ├── istio.py          — sidecar errors, circuit breaker, mTLS, retry budget
    ├── host.py           — CPU, memory, disk I/O, network, file descriptors
    ├── aws.py            — Lambda, RDS, SQS, ECS
    └── http_patterns.py  — 429/401/403/5xx patterns, batch jobs, observability quality
```
