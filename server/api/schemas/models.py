"""
Pydantic models for API request/response validation.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class ConversionRequest(BaseModel):
    """Request body for rule conversion."""

    rule_yaml: str = Field(..., description="Sigma rule as YAML string")
    format: str = Field(
        default="eql",
        description="Target format: eql, esql, lucene, kibana_ndjson, siem_rule, etc.",
    )
    pipeline: str = Field(
        default="ecs_windows",
        description="Field mapping pipeline: ecs_windows, ecs_linux, zeek, kubernetes, macos",
    )
    target_index: Optional[str] = Field(
        default=None,
        description="(Optional) Target index pattern for reference",
    )

    class Config:
        schema_extra = {
            "example": {
                "rule_yaml": "title: Test Rule\ndescription: A test rule\ndetection:\n  selection:\n    Image: test.exe\n  condition: selection",
                "format": "eql",
                "pipeline": "ecs_windows",
            }
        }


class ConversionResponse(BaseModel):
    """Response body for rule conversion."""

    conversion_id: str = Field(..., description="Unique ID for this conversion (idempotent)")
    query_result: str = Field(..., description="The converted query string")
    format: str = Field(..., description="The format that was used")

    class Config:
        schema_extra = {
            "example": {
                "conversion_id": "a1b2c3d4e5f6g7h8",
                "query_result": 'process where image : "test.exe"',
                "format": "eql",
            }
        }


class EventSample(BaseModel):
    """Sample event from test-run results."""

    event_id: str = Field(..., description="Event ID from Elasticsearch")
    timestamp: str = Field(..., description="Event timestamp")
    source: Dict[str, Any] = Field(..., description="Event source fields")

    class Config:
        schema_extra = {
            "example": {
                "event_id": "_12345",
                "timestamp": "2024-01-15T10:23:45Z",
                "source": {"image": "test.exe", "host.name": "WIN-ABC123"},
            }
        }


class TestRunRequest(BaseModel):
    """Request body for testing a rule."""

    rule_yaml: str = Field(..., description="Sigma rule as YAML string")
    index_pattern: str = Field(
        default="*",
        description="Elasticsearch index pattern to query",
    )
    timeframe_hours: int = Field(
        default=24,
        ge=1,
        le=2160,
        description="Hours of recent data to search (1-2160, i.e., 3 months)",
    )
    pipeline: str = Field(
        default="ecs_windows",
        description="Field mapping pipeline used during conversion (ecs_windows, ecs_linux, etc.)",
    )
    query_format: str = Field(
        default="eql",
        description="Format to convert the rule to before executing: eql, esql, or lucene",
    )

    class Config:
        schema_extra = {
            "example": {
                "rule_yaml": "title: Test Rule\n...",
                "index_pattern": "winlogbeat-*",
                "timeframe_hours": 24,
                "pipeline": "ecs_windows",
                "query_format": "eql",
            }
        }


class TestRunResponse(BaseModel):
    """Response body for testing a rule."""

    test_run_id: str = Field(..., description="Unique ID for this test run")
    hit_count: int = Field(..., ge=0, description="Number of events matching the rule")
    sample_events: List[EventSample] = Field(
        ..., description="First N events matching the rule"
    )
    timing_ms: int = Field(..., ge=0, description="Query execution time in milliseconds")

    class Config:
        schema_extra = {
            "example": {
                "test_run_id": "x9y8z7w6v5u4t3s2",
                "hit_count": 42,
                "sample_events": [
                    {
                        "event_id": "_123",
                        "timestamp": "2024-01-15T10:23:45Z",
                        "source": {"image": "test.exe", "host.name": "WIN-ABC"},
                    }
                ],
                "timing_ms": 125,
            }
        }


# ── Field mapping schemas ─────────────────────────────────────────────────────

class FieldSuggestRequest(BaseModel):
    sigma_field: str = Field(..., description="Sigma field name to look up (e.g. 'CommandLine')")
    index_pattern: Optional[str] = Field(None, description="If provided, also search live ES index mappings")
    es_url: Optional[str] = Field(None, description="Elasticsearch base URL (required if index_pattern given)")
    api_key: Optional[str] = Field(None, description="Elasticsearch API key for live mapping fetch")


class FieldSuggestResponse(BaseModel):
    sigma_field: str
    ecs_field: Optional[str] = None
    confidence: Optional[float] = None
    description: Optional[str] = None
    live_fields: List[str] = Field(default_factory=list)


# ── Validation schemas ────────────────────────────────────────────────────────

class ValidationIssue(BaseModel):
    type: str = Field(..., description="'error' or 'warning'")
    rule: str = Field(..., description="Validator rule name")
    message: str = Field(..., description="Human-readable description")


class ValidationRequest(BaseModel):
    rule_yaml: str = Field(..., description="Sigma rule YAML to validate")


class ValidationResponse(BaseModel):
    valid: bool = Field(..., description="True if no errors (warnings allowed)")
    issues: List[ValidationIssue] = Field(default_factory=list)


# ── Cluster-hits schemas ──────────────────────────────────────────────────────

class ClusterBucket(BaseModel):
    value: str
    count: int


class ClusterField(BaseModel):
    field: str
    buckets: List[ClusterBucket]


class ClusterHitsResponse(BaseModel):
    test_run_id: str
    total_hits: int
    clusters: List[ClusterField]


# ── Effectiveness / staleness / quality schemas ───────────────────────────────

class EffectivenessRecord(BaseModel):
    rule_title: str
    rule_yaml_hash: str
    test_run_id: str
    hit_count: int
    index_pattern: str
    query_format: str
    ran_at: str


class EffectivenessResponse(BaseModel):
    rule_title: str
    records: List[EffectivenessRecord]


class StaleRuleEntry(BaseModel):
    rule_title: str
    last_run_at: str
    total_runs: int
    max_hits_in_window: int
    stale_days: int


class StaleRulesResponse(BaseModel):
    stale_rules: List[StaleRuleEntry]
    days: int


class QualityScoreResponse(BaseModel):
    rule_title: str
    score: int
    reasons: List[str]


# ── Schema drift schemas ──────────────────────────────────────────────────────

class SchemaSnapshotRequest(BaseModel):
    index_pattern: str = Field(..., description="Index pattern to snapshot (e.g. 'logs-*', 'so-*')")


class DriftedField(BaseModel):
    field: str
    status: str  # "removed" | "type_changed"
    previous_type: Optional[str] = None
    current_type: Optional[str] = None


class SchemaDriftReport(BaseModel):
    index_pattern: str
    snapshot_taken_at: Optional[str] = None
    checked_at: str
    drifted_fields: List[DriftedField]
    total_fields_snapshot: int
    total_fields_current: int


# ── AI schemas ───────────────────────────────────────────────────────────────

class AIDraftFromIOCsRequest(BaseModel):
    iocs: List[str] = Field(..., description="List of IOCs (IPs, hashes, process names, etc.)")
    index_pattern: str = Field(default="logs-*", description="ES index pattern for context gathering")
    logsource_hint: Optional[str] = Field(None, description="Preferred SIGMA logsource category")


class AIExplainRequest(BaseModel):
    rule_yaml: str = Field(..., description="SIGMA rule YAML to explain")


class AIImproveRequest(BaseModel):
    rule_yaml: str = Field(..., description="SIGMA rule YAML to improve")
    index_pattern: str = Field(default="logs-*", description="ES index pattern for field context")


class AIAlertDraftRequest(BaseModel):
    alert_id: str = Field(..., description="Kibana or SO alert document ID")
    source: str = Field(default="kibana", description="'kibana' or 'so' (Security Onion)")


class AIResultResponse(BaseModel):
    success: bool
    rule_yaml: Optional[str] = None
    explanation: Optional[str] = None
    changes: Optional[str] = None
    source_type: Optional[str] = None
    message: Optional[str] = None


class AIChatMessage(BaseModel):
    role: str = Field(..., description="'user' or 'assistant'")
    content: str


class AIChatRequest(BaseModel):
    messages: List[AIChatMessage] = Field(..., description="Full conversation history")
    rule_context: Optional[str] = Field(None, description="Current rule YAML for editor context")


class AIChatResponse(BaseModel):
    success: bool
    reply: Optional[str] = None
    message: Optional[str] = None


class AlertSummary(BaseModel):
    id: str
    timestamp: Optional[str] = None
    rule_name: Optional[str] = None
    severity: Optional[str] = None
    host_name: Optional[str] = None
    event_module: Optional[str] = None


class AlertListResponse(BaseModel):
    alerts: List[AlertSummary]
    index_pattern: str


# ── Rule registry schemas ─────────────────────────────────────────────────────

class RuleRegistrationRequest(BaseModel):
    kibana_rule_id: str = Field(..., description="Kibana detection rule UUID")
    rule_yaml: str = Field(..., description="Original Sigma rule YAML")
    title: str = Field(..., description="Rule title")


class RuleSourceResponse(BaseModel):
    kibana_rule_id: str
    rule_yaml: str
    title: str
    registered_at: str
