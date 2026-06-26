"""ECS field mapping endpoints."""

from fastapi import APIRouter, Query
from typing import Optional
from schemas.models import FieldSuggestRequest, FieldSuggestResponse
from services.fields import FieldMappingService, ECS_CATALOG

router = APIRouter()
_svc = FieldMappingService()


@router.get(
    "/fields",
    summary="Browse ECS field catalog",
    description="Return the curated ECS field catalog. Use `category` to filter (process, file, network, dns, registry, user, event, host, http, winlog).",
)
async def get_fields(category: Optional[str] = Query(None, description="ECS category to filter by")):
    return _svc.get_catalog(category)


@router.post(
    "/fields/suggest",
    response_model=FieldSuggestResponse,
    summary="Map a Sigma field name to ECS",
    description="Given a Sigma field name (e.g. CommandLine, Image, DestinationIp), returns the best matching ECS field with a confidence score. Optionally fetches live index mappings to extend the suggestion.",
)
async def suggest_field(req: FieldSuggestRequest) -> FieldSuggestResponse:
    match = _svc.suggest(req.sigma_field)

    live_fields: list[str] = []
    if req.index_pattern and req.es_url:
        live_fields = await _svc.get_live_fields(req.index_pattern, req.es_url, req.api_key)

    if match:
        return FieldSuggestResponse(
            sigma_field=req.sigma_field,
            ecs_field=match["ecs_field"],
            confidence=match["confidence"],
            description=match["description"],
            live_fields=live_fields,
        )

    return FieldSuggestResponse(
        sigma_field=req.sigma_field,
        live_fields=live_fields,
    )
