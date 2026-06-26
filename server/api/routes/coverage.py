"""Live ATT&CK coverage endpoint."""

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Any, Dict, List

from services.coverage import compute_coverage, build_navigator_layer

router = APIRouter()


class CoverageRequest(BaseModel):
    rule_yamls: List[str] = Field(
        ...,
        description="List of Sigma rule YAML strings to compute coverage for.",
    )


@router.post(
    "/coverage",
    summary="Compute live ATT&CK technique coverage",
    description="""
Given a list of Sigma rule YAMLs, extract all `attack.t{id}` and `attack.{tactic}` tags
and return a structured MITRE ATT&CK coverage report.

**When to use:** When you want to understand which ATT&CK techniques your current rule set
covers, identify gaps by tactic, or see which rules map to which techniques.

**Response shape:**
- `covered_techniques` — count of distinct techniques across all rules
- `covered_tactics` — list of tactic keys that have at least one rule
- `techniques` — per-technique detail with name, tactic, and which rules cover it
- `by_tactic` — technique IDs grouped by tactic key
- `uncovered_tactics` — tactics with zero coverage
- `rule_index` — per-rule technique list
""",
)
async def coverage(req: CoverageRequest) -> Dict[str, Any]:
    return compute_coverage(req.rule_yamls)


@router.post(
    "/coverage/navigator-export",
    summary="Export coverage as ATT&CK Navigator layer",
    description="""
Computes coverage from a list of Sigma rule YAMLs and returns a valid
MITRE ATT&CK Navigator 4.x layer JSON file. Import it directly into
https://mitre-attack.github.io/attack-navigator/ for stakeholder reporting.

Color gradient: white (0 rules) → green shades → dark green (7+ rules).
""",
)
async def navigator_export(req: CoverageRequest) -> JSONResponse:
    coverage_data = compute_coverage(req.rule_yamls)
    layer = build_navigator_layer(coverage_data)
    return JSONResponse(content=layer)
