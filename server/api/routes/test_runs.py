"""
Test-running routes.

Endpoints:
- POST /v1/test-runs: Test a Sigma rule against live Elasticsearch data
"""

from fastapi import APIRouter, Request, Depends, HTTPException, Query
from schemas.models import TestRunRequest, TestRunResponse, ClusterHitsResponse
from services.testing import TestingService
from services.effectiveness import EffectivenessService
from config import get_settings, Settings
import logging

logger = logging.getLogger(__name__)

router = APIRouter()
testing_service = TestingService()


@router.post("/test-runs", response_model=TestRunResponse)
async def test_rule(
    request_body: TestRunRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
):
    """
    Test a Sigma rule against live Elasticsearch data.

    **Request:**
    - `rule_yaml`: Sigma rule in YAML format (as string)
    - `index_pattern`: Elasticsearch index pattern to query
    - `timeframe_hours`: How many hours of recent data to search

    **Response:**
    - `test_run_id`: Unique identifier for this test run
    - `hit_count`: Number of events matching the rule
    - `sample_events`: First N events (up to max_hits_sample)
    - `timing_ms`: Elasticsearch query execution time in milliseconds
    """
    api_key = getattr(request.state, "elastic_api_key", None)
    logger.info(
        f"Testing rule against index '{request_body.index_pattern}' "
        f"for past {request_body.timeframe_hours} hours"
    )

    result = await testing_service.test_rule(
        rule_yaml=request_body.rule_yaml,
        index_pattern=request_body.index_pattern,
        timeframe_hours=request_body.timeframe_hours,
        pipeline=request_body.pipeline,
        query_format=request_body.query_format,
        elastic_api_key=api_key,
        settings=settings,
    )

    logger.info(f"Test completed: {result.hit_count} hits in {result.timing_ms}ms")

    eff_svc = EffectivenessService(settings)
    await eff_svc.record_test_run(
        rule_yaml=request_body.rule_yaml,
        test_run_id=result.test_run_id,
        hit_count=result.hit_count,
        index_pattern=request_body.index_pattern,
        query_format=request_body.query_format,
        api_key=api_key,
    )

    return result


@router.post(
    "/test-runs/{test_run_id}/cluster-hits",
    response_model=ClusterHitsResponse,
    summary="Cluster hits by top field values",
    description="For a completed test run, return the top contributing field values grouped by ECS field. Useful for identifying candidates to exclude from overly noisy rules.",
)
async def cluster_hits(
    test_run_id: str,
    top_n: int = Query(default=5, ge=1, le=20, description="Top N values per field"),
    settings: Settings = Depends(get_settings),
):
    try:
        return await testing_service.cluster_hits(test_run_id, settings, top_n=top_n)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
