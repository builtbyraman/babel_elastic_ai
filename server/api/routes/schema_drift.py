"""
Schema drift detection routes.

Endpoints:
- POST /v1/schema-drift/snapshot            — snapshot an index pattern's mapping
- POST /v1/schema-drift/snapshot/so         — snapshot all Security Onion patterns
- GET  /v1/schema-drift/report?index=...    — drift report vs. stored snapshot
"""

from fastapi import APIRouter, Depends, Query
from schemas.models import SchemaSnapshotRequest, SchemaDriftReport, DriftedField
from services.schema_drift import SchemaDriftService
from config import get_settings, Settings

router = APIRouter()


@router.post("/schema-drift/snapshot")
async def snapshot_mapping(
    body: SchemaSnapshotRequest,
    settings: Settings = Depends(get_settings),
):
    svc = SchemaDriftService(settings)
    return await svc.snapshot(body.index_pattern)


@router.post("/schema-drift/snapshot/so")
async def snapshot_so_patterns(
    settings: Settings = Depends(get_settings),
):
    """Snapshot all Security Onion index patterns (so-alert-*, so-logs-*, so-import-*)."""
    svc = SchemaDriftService(settings)
    return {"results": await svc.snapshot_all_so()}


@router.get("/schema-drift/report", response_model=SchemaDriftReport)
async def drift_report(
    index_pattern: str = Query(..., description="Index pattern to check (e.g. 'logs-*', 'so-alert-*')"),
    settings: Settings = Depends(get_settings),
):
    svc = SchemaDriftService(settings)
    result = await svc.detect_drift(index_pattern)
    return SchemaDriftReport(
        index_pattern=result["index_pattern"],
        snapshot_taken_at=result.get("snapshot_taken_at"),
        checked_at=result["checked_at"],
        drifted_fields=[DriftedField(**f) for f in result.get("drifted_fields", [])],
        total_fields_snapshot=result.get("total_fields_snapshot", 0),
        total_fields_current=result.get("total_fields_current", 0),
    )
