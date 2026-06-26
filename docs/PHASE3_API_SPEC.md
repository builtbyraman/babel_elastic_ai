Phase 3 — MCP Server: API Specification (summary)

This document contains concise API shapes and examples to be used while implementing the MCP server.

Security
--------
- All endpoints require `Authorization: Bearer <api_key>` header, except health endpoints.
- API keys are tenant-scoped and stored hashed.

Common Error Response (RFC 7807)
---------------------------------
{
  "type": "https://mcp.example.com/errors/invalid-request",
  "status": 400,
  "title": "Invalid request",
  "detail": "Detailed error message",
  "instance": "/v1/conversions"
}

Endpoints (concise)
-------------------

POST /v1/conversions
- Summary: Convert Sigma rule synchronously or queue as job.
- Auth: required
- Request body (JSON):
  {
    "rule_yaml": "string",
    "format": "eql",
    "pipeline": "ecs_windows",
    "idempotency_key": "optional-string"
  }
- Responses:
  - 200: { conversion_id, query_result, format }
  - 202: { job_id }
  - 4xx/5xx: Problem Details

POST /v1/test-runs
- Request body (JSON):
  {
    "rule_yaml": "string",
    "index_pattern": "string",
    "timeframe_hours": 24,
    "target_connector_id": "uuid",
    "run_mode": "sync" | "async"
  }
- Responses:
  - 200 (sync): { test_run_id, hit_count, sample_events, timing_ms }
  - 202 (async): { job_id }

POST /v1/secrets
- Summary: Store connector credentials or auth payloads.
- Request body (JSON):
  {
    "name": "string",
    "type": "api_key" | "bearer" | "basic",
    "value": { ... }
  }
- Responses:
  - 200: { id, name, type, created_at, updated_at }

POST /v1/connectors
- Summary: Register an Elasticsearch connector endpoint.
- Request body (JSON):
  {
    "name": "string",
    "type": "elasticsearch",
    "endpoint": "https://es.example.com:9200",
    "auth_type": "api_key" | "bearer" | "basic",
    "credentials_ref": "string",
    "metadata": { ... }
  }
- Responses:
  - 200: { id, name, type, endpoint, auth_type, credentials_ref, verified, last_checked, metadata, created_at, updated_at }

GET /v1/connectors/{connector_id}
- Summary: Read stored connector details.
- Responses:
  - 200: Connector metadata as above.

POST /v1/connectors/{connector_id}/health
- Summary: Perform a health check against the configured Elasticsearch endpoint using stored auth.
- Responses:
  - 200: { connector_id, verified, status, message, last_checked }

GET /v1/jobs/{job_id}
- Response: { job_id, status, type, created_at, started_at, finished_at, result_preview?, result_url? }

POST /v1/keys
- Create API key for tenant
- Request: { tenant_id, name, scopes, ttl_days }
- Response: { key_id, api_key (plaintext shown once) }

GET /v1/tenants/{tenant_id}/connections
POST /v1/tenants/{tenant_id}/connections
- Connectors management for tenant

GET /v1/status
- Aggregated MCP health for admin and Status Page consumption

Data Models (JSON)
------------------
ConversionResponse
{
  "conversion_id": "hex",
  "query_result": "string",
  "format": "string"
}

TestRunResponse
{
  "test_run_id": "uuid",
  "hit_count": 47,
  "sample_events": [ { "event_id": "", "timestamp": "", "source": {} } ],
  "timing_ms": 245
}

JobStatusResponse
{
  "job_id": "uuid",
  "status": "pending|running|completed|failed",
  "type": "conversion|test-run",
  "created_at": "2026-05-18T...Z",
  "started_at": null,
  "finished_at": null,
  "result_preview": null,
  "result_url": null
}

Notes & Implementation Hints
----------------------------
- Enforce per-tenant isolation: every DB query includes tenant_id.
- Use background workers to run conversions and test-runs.
- For sync paths, micro-optimizations: in-process conversion (pySigma) where safe, otherwise proxy to Phase1 API.

