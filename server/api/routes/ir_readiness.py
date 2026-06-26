"""IR Readiness Report endpoint."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Any, Dict, List

from services.ir_readiness import compute_ir_readiness, SCENARIOS

router = APIRouter()


class IrReadinessRequest(BaseModel):
    scenario: str = Field(..., description="Scenario key: ransomware | credential_theft | lateral_movement | insider_threat")
    rule_yamls: List[str] = Field(..., description="List of Sigma rule YAML strings (title + tags + x-ir-phase)")


@router.get(
    "/ir-readiness/scenarios",
    summary="List available IR readiness scenarios",
)
async def list_scenarios() -> Dict[str, str]:
    return {k: v["display_name"] for k, v in SCENARIOS.items()}


@router.post(
    "/ir-readiness",
    summary="Compute IR readiness gap report",
    description="""
Given a threat scenario and your rule library, returns a phase-by-phase gap report
showing which IR lifecycle phases have ATT&CK technique coverage and which are blind spots.

**Scenarios:** `ransomware`, `credential_theft`, `lateral_movement`, `insider_threat`

**Response includes per-phase:**
- Expected ATT&CK techniques for that phase
- Which are covered by rules vs. missing
- Rules explicitly tagged with `x-ir-phase` for that phase
- Overall technique coverage percentage
""",
)
async def ir_readiness(req: IrReadinessRequest) -> Dict[str, Any]:
    try:
        return compute_ir_readiness(req.scenario, req.rule_yamls)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
