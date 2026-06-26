Phase 3 — MCP Server: Design Specification

Purpose
-------
Provide a robust, multi-tenant MCP (Managed Conversion Platform) server that:
- Provides a stable, authenticated external API for conversions and test-runs.
- Orchestrates workers for long-running/async jobs and schedules.
- Manages tenants, API keys, connectors (customer ES endpoints), quotas and billing metrics.
- Provides observability, admin controls, and health/status information for the Status Page.

Recommendation Summary (quick)
------------------------------
- Language & Framework: Python + FastAPI (same as Phase 1) to maximize reuse of conversion/test-run code.
- Job Queue / Worker: Celery with Redis broker (or RabbitMQ if you expect very large scale); Celery gives mature worker management, retries, and monitoring.
- Metadata DB: PostgreSQL for tenants, jobs, connectors, audit logs.
- Cache & short-lived state: Redis (also used as Celery broker and caching layer).
- Artifact storage: S3-compatible object storage for job artifacts/results.
- Secrets store: HashiCorp Vault or K8s Secrets for production; at minimum use AES-encrypted fields in Postgres.
- Observability: Prometheus metrics, OpenTelemetry traces, logs in JSON to stdout (ELK/Grafana for log/visualization).
- Auth: API keys per-tenant (stored hashed), optional JWT/OIDC for user/admins.

Rationale
---------
- Using Python + FastAPI aligns with Phase 1 (reduces context switching, reuses conversion code), simplifies proxy/embedding.
- Celery + Redis is a pragmatic, battle-tested choice for Python workloads and supports delayed & retry semantics.
- Postgres and S3 are tried-and-true for persistence and large artifacts.

High-level Architecture
-----------------------
- API Layer (FastAPI): Stateless; validates requests, enforces auth & rate-limits, creates job records, returns synchronous or job-id for async.
- Orchestration / Queue: Celery (workers) + Redis broker + Redis cache
- Workers:
  - Conversion worker (can call Phase1 HTTP API or run pySigma locally)
  - Test-run worker (executes queries against configured ES connectors using tenant credentials)
- Storage:
  - Postgres: relational metadata
  - Redis: cache & idempotency keys
  - S3: artifacts (large query outputs, rule archives)
- Secrets: Vault or encrypted DB fields
- Admin UI: web UI for tenant management, connectors, queues, logs, status

API Surface (high-level)
------------------------
- POST /v1/conversions
  - Synchronous by default (if conversion quick and worker can run inline) or async (return job id)
  - Body: { rule_yaml, format, pipeline, tenant_id?, idempotency_key? }
  - Response: 200 { conversion_id, query_result, format } or 202 { job_id }

- POST /v1/test-runs
  - Body: { rule_yaml, index_pattern, timeframe_hours, target_connector_id, run_mode: sync|async }
  - Response (sync): 200 { test_run_id, hit_count, sample_events[], timing_ms }
  - Response (async): 202 { job_id }

- GET /v1/jobs/{job_id}
  - Response: { job_id, status, type, created_at, started_at, finished_at, result_url?, result_preview? }

- POST /v1/tenants
- GET /v1/tenants/{tenant_id}
- POST /v1/tenants/{tenant_id}/connections
- GET /v1/tenants/{tenant_id}/connections
- POST /v1/keys (issue API key)
- GET /v1/status (MCP health, queue lengths, worker counts)

Auth & Multi-tenancy
--------------------
- Primary Auth method: API keys (Bearer). API key metadata: tenant_id, scopes, expiry.
- API keys stored hashed (bcrypt or PBKDF2) and not logged.
- Optionally implement JWT/OIDC for users/admins (for admin console).
- Each request must include header `Authorization: Bearer <api_key>`; server looks up key, resolves tenant_id, and enforces isolation.

Idempotency & Caching
---------------------
- Conversion idempotency by hash: SHA256(rule_yaml|format|pipeline) → conversion_id.
- Support client-provided `Idempotency-Key` header: map to job or conversion result.
- Cache conversion results in Redis (or Postgres cache table) with configurable TTL.

Connector Model (customer ES)
-----------------------------
- Connectors table stores: id, tenant_id, name, type (elasticsearch), endpoint (URL), auth_type (api_key/basic/cloud_id), credentials_ref (secret id), verified (bool), last_checked.
- Workers use connector credentials to create ES clients and run EQL queries. If auth fails, mark connector unhealthy and report.

Data Model (DDL for Postgres - recommended)
-------------------------------------------
-- Tenants
CREATE TABLE tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  owner_email TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- API keys (hashed)
CREATE TABLE api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
  key_id TEXT NOT NULL, -- public id for lookup
  hashed_key TEXT NOT NULL,
  scopes TEXT[],
  expires_at TIMESTAMP WITH TIME ZONE NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Connectors
CREATE TABLE connectors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
  name TEXT,
  type TEXT, -- 'elasticsearch', 'splunk', etc.
  endpoint TEXT,
  credentials_ref TEXT, -- reference to secret in Vault or encrypted blob id
  verified BOOLEAN DEFAULT false,
  last_checked TIMESTAMP WITH TIME ZONE NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

-- Jobs (conversion/test-run)
CREATE TYPE job_status AS ENUM ('pending','running','completed','failed','cancelled');
CREATE TABLE jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID REFERENCES tenants(id),
  type TEXT, -- 'conversion' | 'test-run'
  input_hash TEXT,
  idempotency_key TEXT,
  status job_status DEFAULT 'pending',
  attempts INT DEFAULT 0,
  result_location TEXT, -- s3 path or JSON
  error TEXT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
  started_at TIMESTAMP WITH TIME ZONE NULL,
  finished_at TIMESTAMP WITH TIME ZONE NULL
);

-- Audit
CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NULL,
  actor TEXT,
  action TEXT,
  details JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

API Spec (short-form)
---------------------
- Use OpenAPI 3.0 for full spec; below are concise shapes.

POST /v1/conversions
Request JSON:
{
  "rule_yaml": "string",
  "format": "eql",
  "pipeline": "ecs_windows",
  "idempotency_key": "optional-string"
}

Responses:
- 200 OK
  { "conversion_id": "hex", "query_result": "string", "format": "string" }
- 202 Accepted
  { "job_id": "uuid" }
- 400/401/422/503 as RFC7807 problem details

POST /v1/test-runs
Request JSON:
{
  "rule_yaml": "string",
  "index_pattern": "string",
  "timeframe_hours": 24,
  "target_connector_id": "uuid",
  "run_mode": "sync" | "async"
}

Responses:
- 200 OK (sync result)
- 202 Accepted (async job created)
- 400/401/503 as RFC7807 problem details

Operational & Observability Requirements
----------------------------------------
- Metrics exported to Prometheus:
  - requests_total, requests_duration_seconds, job_queue_size, jobs_processed, jobs_failed, per-tenant usage
- Traces: OpenTelemetry spans for request → conversion → test-run → result
- Logs: structured JSON with `request_id`, `tenant_id`, `job_id` where applicable
- Dashboards: Grafana for metrics, Kibana for logs

Security & Hardening
--------------------
- TLS enforced for all inbound/outbound traffic.
- Rate limiting per-tenant (requests/s and conversions/minute) using Redis token bucket.
- Secrets stored in Vault or encrypted in Postgres (AES-GCM with rotation key).
- Audit logs persisted and immutable; retention policy configurable.
- Regular key rotation and revocation UI/API.

Scaling & Deployment
--------------------
- Deploy API as a K8s Deployment (HPA based on request latency / CPU).
- Workers scaled independently (HPA based on Celery queue backlog).
- Redis cluster for resilience, Postgres with HA (managed RDS), S3 (managed) for artifacts.
- Use readiness/liveness probes and PodDisruptionBudgets.

Failure Modes & Recovery
------------------------
- If a worker fails: job stays in queue; retry policy re-enqueues with backoff. Dead-letter queue stores failing jobs for manual review.
- If connector auth fails repeatedly: mark connector unhealthy, notify tenant via audit and optional webhook.
- If Postgres unavailable: API should return 503; a limited read-only mode could be implemented for status page if desired.

Admin & Billing
---------------
- Emit per-tenant metrics for billing: conversions, test-run seconds, ES query volume.
- Provide admin endpoints to view usage and set quotas.

Testing, QA & Migration
-----------------------
- Unit tests for auth, job lifecycle, connector validation.
- Integration tests that run conversions via Phase1 or local converter and test-runs against an ephemeral ES test cluster.
- Load tests to validate worker scaling (k6 / Locust).
- Migration plan: start with proxying Phase1 endpoints; add local worker converter later. Support hybrid mode.

Milestones & Estimated Effort
-----------------------------
- M3.1: Design & stack selection — 2 days
- M3.2: Auth, tenant model, DB schema & migrations — 3 days
- M3.3: Conversion proxy (sync) + job model — 3 days
- M3.4: Test-run sync worker + connector model — 5 days
- M3.5: Async jobs + Celery worker + DLQ — 4 days
- M3.6: Observability, admin UI, status integration — 3 days
- M3.7: Quotas, billing hooks, production hardening — 4 days
- Buffer & testing — 3 days
Total: ~27 working days (single engineer), can be parallelized across 2 engineers to shorten.

Questions / Decisions Needed
---------------------------
1. Queue choice: Celery+Redis (recommended) vs RabbitMQ+Celery (more robust) vs simpler RQ. Any preference?
2. Secrets: use Vault, or start with encrypted DB fields?
3. Billing: should MCP produce billing-ready metrics or just raw usage metrics for later processing?
4. Connector ownership: will tenants configure connectors via UI (recommended) or will MCP be given connector information offline?
5. Notifications: prefer webhook callbacks, websocket notifications, or only polling for job completion?

Next deliverables I can produce when you confirm choices
- Full OpenAPI 3.0 spec file for MCP endpoints (YAML)
- Postgres migration scripts (SQL) and sample ORM models (SQLAlchemy / Alembic)
- Celery worker skeleton with job handlers and retry policies
- Admin UI wireframes and RBAC model


