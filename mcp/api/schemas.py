from typing import Optional, Dict, Any, List

from pydantic import BaseModel, Field


class ConversionRequest(BaseModel):
    rule_yaml: str = Field(..., description="Sigma rule as YAML string")
    format: str = Field(default="eql", description="Target format: eql, esql, es-qs, dsl_lucene, kibana_ndjson, siem_rule, elastalert")
    pipeline: str = Field(default="ecs_windows", description="Field mapping pipeline: ecs_windows, ecs_linux, zeek, kubernetes, macos")


class TestRunRequest(BaseModel):
    rule_yaml: str = Field(..., description="Sigma rule as YAML string")
    index_pattern: str = Field(default="*", description="Elasticsearch index pattern to query")
    timeframe_hours: int = Field(default=24, ge=1, le=2160, description="Hours of recent data to search (1-2160)")
    connector_id: Optional[str] = Field(default=None, description="Optional connector ID to run the query against")
    pipeline: str = Field(default="ecs_windows", description="Field mapping pipeline: ecs_windows, ecs_linux, zeek, kubernetes, macos")
    query_format: str = Field(default="eql", description="Query format to execute: eql, esql, or es-qs")


class ConnectorRequest(BaseModel):
    name: str = Field(..., description="Connector display name")
    type: str = Field(..., description="Connector type, e.g. elasticsearch")
    endpoint: str = Field(..., description="Connector endpoint URL")
    auth_type: str = Field(..., description="Authentication type: api_key, bearer, or basic")
    credentials_ref: Optional[str] = Field(default=None, description="Name of a stored secret containing credentials")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Connector metadata")


class TaskResponse(BaseModel):
    job_id: str = Field(..., description="Celery job ID")


class TaskStatusResponse(BaseModel):
    job_id: str
    type: str
    status: str
    celery_status: str
    payload: Optional[Dict[str, Any]] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: str
    updated_at: str


class ConnectorResponse(BaseModel):
    id: str
    name: str
    type: str
    endpoint: str
    auth_type: str
    credentials_ref: Optional[str] = None
    verified: bool
    last_checked: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: str
    updated_at: str


class ConnectorHealthResponse(BaseModel):
    connector_id: str
    verified: bool
    status: str
    message: Optional[str] = None
    last_checked: str


class SecretRequest(BaseModel):
    name: str = Field(..., description="Secret name or identifier")
    type: str = Field(..., description="Secret type: api_key, bearer, or basic")
    value: Dict[str, Any] = Field(..., description="Secret payload (will be AES-GCM encrypted at rest)")


class SecretResponse(BaseModel):
    id: str
    name: str
    type: str
    created_at: str
    updated_at: str


# ── Tenant / API key schemas ──────────────────────────────────────────────────

class TenantRequest(BaseModel):
    name: str = Field(..., description="Tenant name (unique)")
    owner_email: Optional[str] = Field(default=None, description="Owner email address")


class TenantResponse(BaseModel):
    id: str
    name: str
    owner_email: Optional[str] = None
    created_at: str


class ApiKeyRequest(BaseModel):
    name: str = Field(..., description="Human-readable name for this key (e.g. 'ci-pipeline')")
    scopes: List[str] = Field(default_factory=lambda: ['*'], description="Permission scopes. Use ['*'] for full access.")
    ttl_days: Optional[int] = Field(default=None, ge=1, description="Days until expiry. Omit for non-expiring.")


class ApiKeyResponse(BaseModel):
    key_id: str = Field(..., description="Key record ID")
    name: str
    api_key: str = Field(..., description="Full API key — shown ONCE. Store it now.")
    scopes: List[str]
    expires_at: Optional[str] = None
    created_at: str
