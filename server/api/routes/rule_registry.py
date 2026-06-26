"""
Rule registry routes.

Endpoints:
- POST /v1/rules/register          — store SIGMA YAML against a Kibana rule ID (called by deploy)
- GET  /v1/rules/source?id=...     — retrieve original SIGMA YAML by Kibana rule ID
"""

from fastapi import APIRouter, Depends, Query, HTTPException
from schemas.models import RuleRegistrationRequest, RuleSourceResponse
from services.rule_registry import RuleRegistryService
from config import get_settings, Settings

router = APIRouter()


@router.post("/rules/register")
async def register_rule(
    body: RuleRegistrationRequest,
    settings: Settings = Depends(get_settings),
):
    svc = RuleRegistryService(settings)
    return await svc.register(
        kibana_rule_id=body.kibana_rule_id,
        rule_yaml=body.rule_yaml,
        title=body.title,
    )


@router.get("/rules/source", response_model=RuleSourceResponse)
async def get_rule_source(
    kibana_rule_id: str = Query(..., description="Kibana detection rule UUID"),
    settings: Settings = Depends(get_settings),
):
    svc = RuleRegistryService(settings)
    record = await svc.get_source(kibana_rule_id)
    if not record:
        raise HTTPException(
            status_code=404,
            detail=f"No Sigma source found for Kibana rule '{kibana_rule_id}'. "
                   "Rule may have been deployed outside sigma_ai.",
        )
    return RuleSourceResponse(**record)
