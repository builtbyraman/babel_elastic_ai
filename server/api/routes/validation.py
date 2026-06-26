"""Rule validation endpoint."""

from fastapi import APIRouter
from schemas.models import ValidationRequest, ValidationResponse, ValidationIssue
from services.validation import validate_rule

router = APIRouter()


@router.post(
    "/rules/validate",
    response_model=ValidationResponse,
    summary="Validate a Sigma rule",
    description="Run the rule through pySigma's validator suite. Returns a list of errors and warnings. `valid` is true when there are no errors (warnings are allowed).",
)
async def validate(req: ValidationRequest) -> ValidationResponse:
    raw_issues = validate_rule(req.rule_yaml)
    issues = [ValidationIssue(**i) for i in raw_issues]
    has_errors = any(i.type == "error" for i in issues)
    return ValidationResponse(valid=not has_errors, issues=issues)
