"""
Test-running service.

Handles converting Sigma rules to EQL / ES|QL / Lucene and executing them
against a live Elasticsearch cluster to return hit counts and sample events.
"""

from schemas.models import TestRunResponse, EventSample, ClusterHitsResponse, ClusterField, ClusterBucket
from services.conversion import ConversionService
from middleware.errors import InvalidRuleError, ElasticsearchError
from config import Settings
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import TransportError as ElasticsearchException
import httpx
import time

logger = logging.getLogger(__name__)

TESTABLE_FORMATS = {"eql", "esql", "es-qs", "dsl_lucene"}

# In-memory cache: test_run_id → (TestRunResponse, settings, index_pattern, elastic_api_key)
_result_cache: Dict[str, Dict[str, Any]] = {}


class TestingService:
    """Service for testing Sigma rules against live Elasticsearch."""

    def __init__(self):
        self.conversion_service = ConversionService()

    async def test_rule(
        self,
        rule_yaml: str,
        index_pattern: str,
        timeframe_hours: int,
        pipeline: str = "ecs_windows",
        query_format: str = "eql",
        elastic_api_key: Optional[str] = None,
        settings: Settings = None,
    ) -> TestRunResponse:
        """Convert a Sigma rule and execute it against Elasticsearch."""
        if query_format not in TESTABLE_FORMATS:
            raise InvalidRuleError(
                f"Format '{query_format}' cannot be executed as a query. "
                f"Use one of: {', '.join(sorted(TESTABLE_FORMATS))}",
                instance="/v1/test-runs",
            )

        logger.info(f"Testing rule ({query_format}) against {index_pattern} for {timeframe_hours}h")
        test_run_id = self._generate_test_run_id(rule_yaml, index_pattern, timeframe_hours, query_format)

        try:
            conversion = await self.conversion_service.convert_rule(
                rule_yaml=rule_yaml,
                format=query_format,
                pipeline=pipeline,
                settings=settings,
            )
            query = conversion.query_result
        except Exception as e:
            raise InvalidRuleError(
                f"Failed to convert rule to {query_format}: {str(e)}", instance="/v1/test-runs"
            )

        try:
            if query_format == "eql":
                hit_count, sample_events, timing_ms = await self._execute_eql_query(
                    query, index_pattern, timeframe_hours, elastic_api_key, settings
                )
            elif query_format == "esql":
                hit_count, sample_events, timing_ms = await self._execute_esql_query(
                    query, index_pattern, timeframe_hours, elastic_api_key, settings
                )
            else:
                hit_count, sample_events, timing_ms = await self._execute_lucene_query(
                    query, index_pattern, timeframe_hours, elastic_api_key, settings
                )
        except ElasticsearchException as e:
            raise ElasticsearchError(f"Elasticsearch query failed: {str(e)}", instance="/v1/test-runs")
        except Exception as e:
            raise ElasticsearchError(f"Test execution failed: {str(e)}", instance="/v1/test-runs")

        result = TestRunResponse(
            test_run_id=test_run_id,
            hit_count=hit_count,
            sample_events=sample_events,
            timing_ms=timing_ms,
        )

        # Cache metadata for cluster-hits queries
        _result_cache[test_run_id] = {
            "index_pattern": index_pattern,
            "timeframe_hours": timeframe_hours,
            "query_format": query_format,
            "pipeline": pipeline,
            "elastic_api_key": elastic_api_key,
            "query": query,
        }

        return result

    # ── EQL ───────────────────────────────────────────────────────────────────

    async def _execute_eql_query(
        self,
        eql_query: str,
        index_pattern: str,
        timeframe_hours: int,
        elastic_api_key: Optional[str],
        settings: Settings,
    ) -> tuple[int, List[EventSample], int]:
        client = self._make_client(elastic_api_key, settings)
        try:
            now = datetime.utcnow()
            time_gte = (now - timedelta(hours=timeframe_hours)).isoformat() + "Z"
            body = {
                "query": eql_query,
                "size": settings.test_run_max_hits_sample,
                "filter": {"range": {"@timestamp": {"gte": time_gte, "lte": now.isoformat() + "Z"}}},
            }
            start = time.time()
            response = client.eql.search(index=index_pattern, body=body)
            timing_ms = int((time.time() - start) * 1000)
            hits = response.get("hits", {}).get("hits", [])
            hit_count = response.get("hits", {}).get("total", {}).get("value", len(hits))
            return hit_count, self._build_samples(hits), timing_ms
        finally:
            client.close()

    # ── ES|QL ─────────────────────────────────────────────────────────────────

    async def _execute_esql_query(
        self,
        esql_query: str,
        index_pattern: str,
        timeframe_hours: int,
        elastic_api_key: Optional[str],
        settings: Settings,
    ) -> tuple[int, List[EventSample], int]:
        """Execute an ES|QL query via direct HTTP (elasticsearch-py < 8.11 has no native esql client)."""
        now = datetime.utcnow()
        time_gte = (now - timedelta(hours=timeframe_hours)).isoformat() + "Z"

        # Inject a WHERE time filter if not already present
        time_filter = f'| WHERE @timestamp >= "{time_gte}"'
        full_query = esql_query if "| WHERE" in esql_query else f"{esql_query}\n{time_filter}"

        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if elastic_api_key:
            headers["Authorization"] = f"ApiKey {elastic_api_key}"

        url = f"{settings.elasticsearch_url()}/_esql"
        body = {"query": full_query}

        start = time.time()
        async with httpx.AsyncClient(timeout=settings.test_run_timeout_seconds) as client:
            resp = await client.post(url, json=body, headers=headers)
            resp.raise_for_status()
        timing_ms = int((time.time() - start) * 1000)

        data = resp.json()
        columns = [col["name"] for col in data.get("columns", [])]
        rows = data.get("values", [])
        hit_count = len(rows)

        samples: List[EventSample] = []
        for row in rows[:settings.test_run_max_hits_sample]:
            source = dict(zip(columns, row))
            samples.append(EventSample(
                event_id=str(source.get("_id", "")),
                timestamp=str(source.get("@timestamp", "")),
                source=source,
            ))
        return hit_count, samples, timing_ms

    # ── Lucene / Query DSL ────────────────────────────────────────────────────

    async def _execute_lucene_query(
        self,
        lucene_query: str,
        index_pattern: str,
        timeframe_hours: int,
        elastic_api_key: Optional[str],
        settings: Settings,
    ) -> tuple[int, List[EventSample], int]:
        client = self._make_client(elastic_api_key, settings)
        try:
            now = datetime.utcnow()
            time_gte = (now - timedelta(hours=timeframe_hours)).isoformat() + "Z"
            body = {
                "query": {
                    "bool": {
                        "must": [{"query_string": {"query": lucene_query}}],
                        "filter": [{"range": {"@timestamp": {"gte": time_gte, "lte": now.isoformat() + "Z"}}}],
                    }
                },
                "size": settings.test_run_max_hits_sample,
            }
            start = time.time()
            response = client.search(index=index_pattern, body=body)
            timing_ms = int((time.time() - start) * 1000)
            hits = response.get("hits", {}).get("hits", [])
            hit_count = response.get("hits", {}).get("total", {}).get("value", len(hits))
            return hit_count, self._build_samples(hits), timing_ms
        finally:
            client.close()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _make_client(self, elastic_api_key: Optional[str], settings: Settings) -> Elasticsearch:
        from config import make_es_client
        return make_es_client(settings, elastic_api_key, es_cls=Elasticsearch)

    def _build_samples(self, hits: list) -> List[EventSample]:
        return [
            EventSample(
                event_id=hit.get("_id", ""),
                timestamp=hit.get("_source", {}).get("@timestamp", ""),
                source=hit.get("_source", {}),
            )
            for hit in hits
        ]

    async def cluster_hits(
        self,
        test_run_id: str,
        settings: Settings,
        top_n: int = 5,
    ) -> ClusterHitsResponse:
        """
        For a previous test run, aggregate the top field values to suggest exclusions.
        Uses a terms aggregation on the fields that appeared in the Sigma detection.
        """
        cached = _result_cache.get(test_run_id)
        if not cached:
            raise ValueError(f"Test run '{test_run_id}' not found in cache. Re-run the test first.")

        index_pattern = cached["index_pattern"]
        timeframe_hours = cached["timeframe_hours"]
        elastic_api_key = cached["elastic_api_key"]
        query = cached["query"]
        query_format = cached["query_format"]

        # Build a filter query to count matching docs and aggregate top field values
        now = datetime.utcnow()
        time_gte = (now - timedelta(hours=timeframe_hours)).isoformat() + "Z"

        # Use a broad match_all + filter for the time window; field aggs over common ECS fields
        cluster_fields = [
            "process.executable", "process.name", "user.name", "host.hostname",
            "destination.ip", "destination.port", "source.ip", "event.code",
            "file.path", "registry.path",
        ]

        aggs: dict = {}
        for f in cluster_fields:
            safe_key = f.replace(".", "_")
            aggs[safe_key] = {"terms": {"field": f, "size": top_n}}

        body: dict = {
            "size": 0,
            "query": {"range": {"@timestamp": {"gte": time_gte}}},
            "aggs": aggs,
        }

        client = self._make_client(elastic_api_key, settings)
        try:
            response = client.search(index=index_pattern, body=body)
        finally:
            client.close()

        agg_result = response.get("aggregations", {})
        total = response.get("hits", {}).get("total", {}).get("value", 0)

        clusters: List[ClusterField] = []
        for f in cluster_fields:
            safe_key = f.replace(".", "_")
            buckets_raw = agg_result.get(safe_key, {}).get("buckets", [])
            if not buckets_raw:
                continue
            buckets = [ClusterBucket(value=str(b["key"]), count=b["doc_count"]) for b in buckets_raw]
            clusters.append(ClusterField(field=f, buckets=buckets))

        return ClusterHitsResponse(
            test_run_id=test_run_id,
            total_hits=total,
            clusters=clusters,
        )

    def _generate_test_run_id(
        self, rule_yaml: str, index_pattern: str, timeframe_hours: int, query_format: str
    ) -> str:
        combined = f"{rule_yaml}:{index_pattern}:{timeframe_hours}:{query_format}"
        return hashlib.sha256(combined.encode()).hexdigest()[:16]
