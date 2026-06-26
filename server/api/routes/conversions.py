"""
Sigma rule conversion routes.

Endpoints:
- POST /v1/conversions: Convert Sigma rule to target format (EQL, Lucene, ES|QL, etc.)
"""

from fastapi import APIRouter, Request, Depends
from schemas.models import ConversionRequest, ConversionResponse
from services.conversion import ConversionService
from config import get_settings, Settings
import logging

logger = logging.getLogger(__name__)

router = APIRouter()
conversion_service = ConversionService()


@router.post("/conversions", response_model=ConversionResponse)
async def convert_sigma_rule(
    request_body: ConversionRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
):
    """
    Convert a Sigma rule to the specified format.

    **Request:**
    - `rule_yaml`: Sigma rule in YAML format (as string)
    - `format`: Output format (eql, esql, lucene, kibana_ndjson, siem_rule, etc.)
    - `pipeline`: Field mapping pipeline (ecs_windows, ecs_linux, zeek, kubernetes, macos)

    **Response:**
    - `conversion_id`: Unique identifier for this conversion (hash-based for idempotency)
    - `query_result`: The converted query string
    - `format`: The format that was used
    """
    logger.info(
        f"Converting rule to format: {request_body.format}, "
        f"pipeline: {request_body.pipeline}"
    )

    result = await conversion_service.convert_rule(
        rule_yaml=request_body.rule_yaml,
        format=request_body.format,
        pipeline=request_body.pipeline,
        settings=settings,
    )

    logger.info(f"Conversion successful: {result.conversion_id}")
    return result
