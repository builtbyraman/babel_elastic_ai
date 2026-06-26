"""
Rule effectiveness, stale detection, and quality scoring routes.

Endpoints:
- GET  /v1/rules/effectiveness?rule_title=X  — test run history for a rule
- GET  /v1/rules/stale?days=30               — rules with no hits in N days
- POST /v1/rules/quality                     — composite quality score
"""

from fastapi import APIRouter, Depends, Query
from schemas.models import (
    EffectivenessResponse, EffectivenessRecord,
    StaleRulesResponse, StaleRuleEntry,
    QualityScoreResponse, ValidationRequest,
)
from services.effectiveness import EffectivenessService
from config import get_settings, Settings
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/rules/effectiveness", response_model=EffectivenessResponse)
async def get_effectiveness(
    rule_title: str = Query(..., description="Rule title to fetch history for"),
    limit: int = Query(default=20, ge=1, le=100),
    settings: Settings = Depends(get_settings),
):
    svc = EffectivenessService(settings)
    records = await svc.get_effectiveness(rule_title, limit=limit)
    return EffectivenessResponse(
        rule_title=rule_title,
        records=[EffectivenessRecord(**r) for r in records],
    )


@router.get("/rules/stale", response_model=StaleRulesResponse)
async def get_stale_rules(
    days: int = Query(default=30, ge=1, le=365, description="Look-back window in days"),
    settings: Settings = Depends(get_settings),
):
    svc = EffectivenessService(settings)
    stale = await svc.get_stale_rules(days=days)
    return StaleRulesResponse(
        stale_rules=[StaleRuleEntry(**r) for r in stale],
        days=days,
    )


@router.post("/rules/quality", response_model=QualityScoreResponse)
async def get_quality_score(
    body: ValidationRequest,
    settings: Settings = Depends(get_settings),
):
    """
    Compute a 0-100 quality score for a rule.
    Runs validation inline and combines with effectiveness history.
    """
    from services.validation import validate_rule
    raw_issues = validate_rule(body.rule_yaml)
    errors   = sum(1 for i in raw_issues if i.get("type") == "error")
    warnings = sum(1 for i in raw_issues if i.get("type") == "warning")

    eff_svc = EffectivenessService(settings)
    result = await eff_svc.compute_quality_score(
        rule_yaml=body.rule_yaml,
        validation_errors=errors,
        validation_warnings=warnings,
    )
    return QualityScoreResponse(**result)
