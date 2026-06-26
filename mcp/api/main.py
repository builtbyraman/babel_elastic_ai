from datetime import datetime
import logging
import os
from typing import Any, Dict, List, Optional

import redis as _redis
import requests
from celery import Celery
from celery.result import AsyncResult
from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from prometheus_fastapi_instrumentator import Instrumentator
from sqlalchemy import text
from auth import get_current_tenant, get_db
from db import run_migrations, seed_bootstrap, SessionLocal
from crud import (
    create_job,
    get_job,
    update_job_status,
    create_connector,
    list_connectors,
    get_connector,
    update_connector_status,
    create_secret,
    get_secret,
    get_secret_value,
    create_tenant,
    create_api_key,
    write_audit_log,
)
from models import Tenant
from schemas import (
    ConversionRequest,
    ConnectorRequest,
    ConnectorResponse,
    ConnectorHealthResponse,
    SecretRequest,
    SecretResponse,
    TaskResponse,
    TaskStatusResponse,
    TenantRequest,
    TenantResponse,
    ApiKeyRequest,
    ApiKeyResponse,
    TestRunRequest,
)
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Sigma AI — MCP API",
    description="""
Sigma AI Managed Conversion Platform — async job orchestration for Sigma rule conversion and testing.

## Tools for AI agents

| Endpoint | When to use |
|---|---|
| `POST /v1/conversions` | Convert a Sigma rule to EQL, ES\|QL, Lucene, or other formats. Returns `job_id`. |
| `POST /v1/test-runs` | Run a converted query against live Elasticsearch. Returns `job_id`. |
| `GET /v1/jobs/{job_id}` | Poll an async job until `status` is `SUCCESS` or `FAILURE`. |
| `POST /v1/connectors` | Register a customer Elasticsearch endpoint. |
| `POST /v1/connectors/{id}/health` | Verify a connector is reachable. |
| `POST /v1/secrets` | Store encrypted connector credentials. |
| `GET /v1/fields` | Browse the ECS field catalog by category. |
| `POST /v1/fields/suggest` | Map a Sigma field name to its ECS equivalent. |
| `POST /v1/rules/validate` | Validate a Sigma rule YAML — errors and warnings. |
| `POST /v1/test-runs/{id}/cluster-hits` | Cluster backtest hits by top field values (exclusion candidates). |
| `POST /v1/coverage` | Compute live ATT\&CK technique coverage from a set of Sigma rules. |

## Authentication
All endpoints (except `/health` and `/metrics`) require `Authorization: Bearer <api_key>`.
Issue keys via `POST /v1/keys` (requires an existing key) or via the bootstrap env vars on first startup.
""",
    version="2.0.0",
)

BROKER = os.getenv('CELERY_BROKER_URL', 'redis://redis:6379/0')
RESULT_BACKEND = os.getenv('RESULT_BACKEND', 'redis://redis:6379/1')
MCP_API_BACKEND = os.getenv('MCP_API_BACKEND', 'http://host.docker.internal:8000/v1')

celery_app = Celery('mcp_worker', broker=BROKER, backend=RESULT_BACKEND)
celery_app.conf.task_routes = {
    'mcp.worker.tasks.convert_rule_task': {'queue': 'conversions'},
    'mcp.worker.tasks.test_rule_task': {'queue': 'test-runs'},
}

# Prometheus metrics — exposes /metrics
Instrumentator().instrument(app).expose(app, include_in_schema=False)


@app.on_event('startup')
def startup_event():
    run_migrations()
    seed_bootstrap()


@app.get('/health', include_in_schema=False)
async def health():
    return {'status': 'ok', 'service': 'mcp-api'}


# ── Tenant management ─────────────────────────────────────────────────────────

@app.post(
    '/v1/tenants',
    response_model=TenantResponse,
    summary="Create a tenant",
    description="Creates a new tenant. Requires an existing API key with '*' scope.",
)
async def create_tenant_route(
    req: TenantRequest,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_db),
):
    new_tenant = create_tenant(session, name=req.name, owner_email=req.owner_email or '')
    write_audit_log(session, action='tenant.created', tenant_id=tenant.id,
                    resource_type='tenant', resource_id=new_tenant.id,
                    details={'name': new_tenant.name})
    return TenantResponse(
        id=new_tenant.id,
        name=new_tenant.name,
        owner_email=new_tenant.owner_email,
        created_at=new_tenant.created_at.isoformat(),
    )


# ── API key management ────────────────────────────────────────────────────────

@app.post(
    '/v1/keys',
    response_model=ApiKeyResponse,
    summary="Issue an API key",
    description="Creates an API key for the calling tenant. The `api_key` field is shown **once** — store it immediately.",
)
async def issue_api_key(
    req: ApiKeyRequest,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_db),
):
    row, plaintext = create_api_key(
        session,
        tenant_id=tenant.id,
        name=req.name,
        scopes=req.scopes,
        ttl_days=req.ttl_days,
    )
    write_audit_log(session, action='api_key.issued', tenant_id=tenant.id,
                    resource_type='api_key', resource_id=row.id,
                    details={'name': req.name, 'scopes': req.scopes})
    return ApiKeyResponse(
        key_id=row.id,
        name=row.name,
        api_key=plaintext,
        scopes=row.scopes,
        expires_at=row.expires_at.isoformat() if row.expires_at else None,
        created_at=row.created_at.isoformat(),
    )


# ── Conversions ───────────────────────────────────────────────────────────────

@app.post(
    '/v1/conversions',
    response_model=TaskResponse,
    summary="Convert a Sigma rule (async)",
    description="""
Convert a Sigma detection rule to a target query format.

**When to use:** Call this first when given a Sigma rule YAML. Returns a `job_id` immediately;
poll `GET /v1/jobs/{job_id}` until `status` is `SUCCESS`, then read `result.query_result`.

**Formats:** `eql` (default), `esql`, `es-qs` (Lucene), `dsl_lucene`, `kibana_ndjson`, `siem_rule`, `elastalert`.
""",
)
async def conversions(
    req: ConversionRequest,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_db),
):
    job = create_job(session, 'conversion', req.dict(), tenant_id=tenant.id)
    celery_app.send_task(
        'mcp.worker.tasks.convert_rule_task',
        args=[req.rule_yaml, req.format, req.pipeline],
        task_id=job.id,
    )
    update_job_status(session, job.id, 'PENDING', celery_id=job.id)
    write_audit_log(session, action='conversion.queued', tenant_id=tenant.id,
                    resource_type='job', resource_id=job.id,
                    details={'format': req.format, 'pipeline': req.pipeline})
    return {'job_id': job.id}


# ── Test runs ─────────────────────────────────────────────────────────────────

def _resolve_connector_auth(connector, session: Session, tenant_id: str) -> Dict[str, str]:
    """Decrypt connector credentials and return auth headers."""
    if not connector.credentials_ref:
        return {}
    value = get_secret_value(session, connector.credentials_ref, tenant_id=tenant_id)
    if not value:
        return {}
    if connector.auth_type == 'api_key':
        return {'Authorization': f"ApiKey {value.get('key', '')}"}
    if connector.auth_type == 'bearer':
        return {'Authorization': f"Bearer {value.get('token', '')}"}
    return {}


@app.post(
    '/v1/test-runs',
    response_model=TaskResponse,
    summary="Run a Sigma rule against live Elasticsearch (async)",
    description="""
Convert a Sigma rule and execute it against a live Elasticsearch cluster.

Returns a `job_id`; poll `GET /v1/jobs/{job_id}` for results.

**Result shape (on SUCCESS):** `{ hit_count, sample_events, timing_ms }`
""",
)
async def test_runs(
    req: TestRunRequest,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_db),
):
    # Resolve connector auth at dispatch time (API decrypts; worker never touches secrets)
    resolved_auth_headers: Dict[str, str] = {}
    connector_endpoint: Optional[str] = None

    if req.connector_id:
        connector = get_connector(session, req.connector_id, tenant_id=tenant.id)
        if not connector:
            raise HTTPException(status_code=404, detail='Connector not found')
        resolved_auth_headers = _resolve_connector_auth(connector, session, tenant.id)
        connector_endpoint = connector.endpoint

    job = create_job(session, 'test_run', req.dict(), tenant_id=tenant.id)
    celery_app.send_task(
        'mcp.worker.tasks.test_rule_task',
        args=[
            req.rule_yaml,
            req.index_pattern,
            req.timeframe_hours,
            resolved_auth_headers,
            connector_endpoint,
            req.pipeline,
            req.query_format,
        ],
        task_id=job.id,
    )
    update_job_status(session, job.id, 'PENDING', celery_id=job.id)
    write_audit_log(session, action='test_run.queued', tenant_id=tenant.id,
                    resource_type='job', resource_id=job.id)
    return {'job_id': job.id}


# ── Job status ────────────────────────────────────────────────────────────────

@app.get(
    '/v1/jobs/{job_id}',
    response_model=TaskStatusResponse,
    summary="Poll async job status",
    description="Poll until `status` is `SUCCESS` or `FAILURE` (every 1–2 seconds).",
)
async def job_status(
    job_id: str,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_db),
):
    job = get_job(session, job_id, tenant_id=tenant.id)
    if not job:
        raise HTTPException(status_code=404, detail='Job not found')
    celery_result = AsyncResult(job_id, app=celery_app)
    return TaskStatusResponse(
        job_id=job.id,
        type=job.type,
        status=job.status,
        celery_status=celery_result.status,
        payload=job.payload,
        result=job.result,
        error=job.error,
        created_at=job.created_at.isoformat(),
        updated_at=job.updated_at.isoformat(),
    )


# ── Connectors ────────────────────────────────────────────────────────────────

@app.post('/v1/connectors', response_model=ConnectorResponse)
async def create_connector_route(
    req: ConnectorRequest,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_db),
):
    connector = create_connector(
        session,
        name=req.name,
        connector_type=req.type,
        endpoint=req.endpoint,
        auth_type=req.auth_type,
        tenant_id=tenant.id,
        credentials_ref=req.credentials_ref,
        metadata=req.metadata,
    )
    write_audit_log(session, action='connector.created', tenant_id=tenant.id,
                    resource_type='connector', resource_id=connector.id)
    return _connector_response(connector)


@app.get('/v1/connectors', response_model=List[ConnectorResponse])
async def list_connectors_route(
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_db),
):
    return [_connector_response(c) for c in list_connectors(session, tenant_id=tenant.id)]


@app.get('/v1/connectors/{connector_id}', response_model=ConnectorResponse)
async def get_connector_route(
    connector_id: str,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_db),
):
    connector = get_connector(session, connector_id, tenant_id=tenant.id)
    if not connector:
        raise HTTPException(status_code=404, detail='Connector not found')
    return _connector_response(connector)


@app.post('/v1/connectors/{connector_id}/health', response_model=ConnectorHealthResponse)
async def check_connector_health(
    connector_id: str,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_db),
):
    connector = get_connector(session, connector_id, tenant_id=tenant.id)
    if not connector:
        raise HTTPException(status_code=404, detail='Connector not found')

    headers, auth = _build_connector_auth_requests(connector, session, tenant.id)
    health_url = connector.endpoint.rstrip('/') + '/_cluster/health?level=cluster'

    try:
        resp = requests.get(health_url, headers=headers, auth=auth, timeout=15)
        resp.raise_for_status()
        payload = resp.json()
        verified = True
        message = f"Elasticsearch cluster is {payload.get('status', 'unknown')}"
    except requests.RequestException as e:
        verified = False
        message = str(e)

    now_iso = datetime.utcnow().isoformat() + 'Z'
    update_connector_status(session, connector_id, verified, last_checked=now_iso)
    write_audit_log(session, action='connector.health_checked', tenant_id=tenant.id,
                    resource_type='connector', resource_id=connector_id,
                    details={'verified': verified})
    return ConnectorHealthResponse(
        connector_id=connector_id,
        verified=verified,
        status='ok' if verified else 'error',
        message=message,
        last_checked=now_iso,
    )


# ── Secrets ───────────────────────────────────────────────────────────────────

@app.post('/v1/secrets', response_model=SecretResponse)
async def create_secret_route(
    req: SecretRequest,
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_db),
):
    secret = create_secret(session, req.name, req.type, req.value, tenant_id=tenant.id)
    write_audit_log(session, action='secret.stored', tenant_id=tenant.id,
                    resource_type='secret', resource_id=secret.id,
                    details={'name': req.name, 'type': req.type})
    return SecretResponse(
        id=secret.id,
        name=secret.name,
        type=secret.type,
        created_at=secret.created_at.isoformat(),
        updated_at=secret.updated_at.isoformat(),
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _connector_response(c) -> ConnectorResponse:
    return ConnectorResponse(
        id=c.id,
        name=c.name,
        type=c.type,
        endpoint=c.endpoint,
        auth_type=c.auth_type,
        credentials_ref=c.credentials_ref,
        verified=c.verified,
        last_checked=c.last_checked.isoformat() if c.last_checked else None,
        metadata=c.metadata_data,
        created_at=c.created_at.isoformat(),
        updated_at=c.updated_at.isoformat(),
    )


def _build_connector_auth_requests(connector, session: Session, tenant_id: str):
    """Build headers + auth tuple for the `requests` library (used in health checks)."""
    headers = {}
    auth = None
    value = get_secret_value(session, connector.credentials_ref, tenant_id=tenant_id) if connector.credentials_ref else None
    if value:
        if connector.auth_type == 'api_key':
            headers['Authorization'] = f"ApiKey {value.get('key', '')}"
        elif connector.auth_type == 'bearer':
            headers['Authorization'] = f"Bearer {value.get('token', '')}"
        elif connector.auth_type == 'basic':
            from requests.auth import HTTPBasicAuth
            auth = HTTPBasicAuth(value.get('username', ''), value.get('password', ''))
    return headers, auth


def _phase1_headers() -> dict:
    api_key = os.getenv('SIGMA_API_KEY', '')
    return {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'} if api_key \
        else {'Content-Type': 'application/json'}


def _phase1_proxy(method: str, path: str, **kwargs) -> requests.Response:
    url = f"{MCP_API_BACKEND}{path}"
    return requests.request(method, url, headers=_phase1_headers(), timeout=30, **kwargs)


# ── Status ────────────────────────────────────────────────────────────────────

@app.get(
    '/v1/status',
    summary="MCP platform health",
    description="Returns queue depths, worker counts, and component health. Useful for ops dashboards and status pages.",
)
async def platform_status(
    tenant: Tenant = Depends(get_current_tenant),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    # Postgres
    try:
        session.execute(text('SELECT 1'))
        postgres_ok = True
    except Exception:
        postgres_ok = False

    # Redis + queue lengths
    try:
        r = _redis.from_url(BROKER, socket_connect_timeout=2)
        r.ping()
        conv_depth = r.llen('conversions')
        test_depth = r.llen('test-runs')
        redis_ok = True
    except Exception:
        conv_depth = test_depth = -1
        redis_ok = False

    # Celery workers
    try:
        inspect = celery_app.control.inspect(timeout=2)
        active = inspect.active() or {}
        worker_count = len(active)
        active_tasks = sum(len(v) for v in active.values())
    except Exception:
        worker_count = active_tasks = -1

    overall = 'ok' if (postgres_ok and redis_ok) else 'degraded'

    return {
        'status': overall,
        'components': {
            'postgres': 'ok' if postgres_ok else 'error',
            'redis': 'ok' if redis_ok else 'error',
        },
        'queues': {
            'conversions': conv_depth,
            'test-runs': test_depth,
        },
        'workers': {
            'count': worker_count,
            'active_tasks': active_tasks,
        },
    }


# ── Fields proxy (→ Phase 1) ──────────────────────────────────────────────────

@app.get(
    '/v1/fields',
    summary="Browse ECS field catalog",
    description="Proxies to Phase 1 API. Returns the curated ECS field catalog, optionally filtered by category.",
)
async def get_fields(
    category: Optional[str] = Query(None),
    tenant: Tenant = Depends(get_current_tenant),
) -> Any:
    params = {'category': category} if category else {}
    try:
        resp = _phase1_proxy('GET', '/fields', params=params)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=str(e))


class FieldSuggestRequest(BaseModel):
    sigma_field: str = Field(..., description="Sigma field name to map (e.g. 'CommandLine')")
    index_pattern: Optional[str] = None
    es_url: Optional[str] = None
    api_key: Optional[str] = None


@app.post(
    '/v1/fields/suggest',
    summary="Map a Sigma field to ECS",
    description="Proxies to Phase 1 API. Given a Sigma field name, returns the best matching ECS field with a confidence score.",
)
async def suggest_field(
    req: FieldSuggestRequest,
    tenant: Tenant = Depends(get_current_tenant),
) -> Any:
    try:
        resp = _phase1_proxy('POST', '/fields/suggest', json=req.dict())
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=str(e))


# ── Validation proxy (→ Phase 1) ──────────────────────────────────────────────

class ValidateRequest(BaseModel):
    rule_yaml: str = Field(..., description="Sigma rule YAML to validate")


@app.post(
    '/v1/rules/validate',
    summary="Validate a Sigma rule",
    description="Proxies to Phase 1 API. Runs the rule through pySigma's validator suite and returns errors and warnings.",
)
async def validate_rule(
    req: ValidateRequest,
    tenant: Tenant = Depends(get_current_tenant),
) -> Any:
    try:
        resp = _phase1_proxy('POST', '/rules/validate', json=req.dict())
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=str(e))


# ── Coverage ──────────────────────────────────────────────────────────────────

class CoverageRequest(BaseModel):
    rule_yamls: List[str] = Field(
        ...,
        description="List of Sigma rule YAML strings to compute ATT&CK coverage for.",
    )


@app.post(
    '/v1/coverage',
    summary="Compute live ATT&CK technique coverage",
    description="""
Given a list of Sigma rule YAMLs, returns a structured MITRE ATT&CK coverage report.

**Response includes:**
- Which techniques are covered and by which rules
- Coverage grouped by tactic
- Uncovered tactics (gaps)
- Per-rule technique index

Use this when you want to identify coverage gaps before recommending new detection rules.
""",
)
async def coverage(
    req: CoverageRequest,
    tenant: Tenant = Depends(get_current_tenant),
) -> Any:
    # Run directly (no pySigma needed, just YAML + regex)
    try:
        resp = _phase1_proxy('POST', '/coverage', json=req.dict())
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=502, detail=str(e))
