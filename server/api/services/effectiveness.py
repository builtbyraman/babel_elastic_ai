"""
Rule effectiveness tracking service.

Persists test-run results per rule in the .sigma-effectiveness ES index,
enabling stale-rule detection and quality scoring.
"""

import hashlib
import logging
from datetime import datetime, timedelta
from typing import Optional, List

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError, TransportError as ElasticsearchException

from config import Settings

logger = logging.getLogger(__name__)

INDEX = ".sigma-effectiveness"

MAPPING = {
    "mappings": {
        "properties": {
            "rule_title":    {"type": "keyword"},
            "rule_yaml_hash":{"type": "keyword"},
            "test_run_id":   {"type": "keyword"},
            "hit_count":     {"type": "integer"},
            "index_pattern": {"type": "keyword"},
            "query_format":  {"type": "keyword"},
            "ran_at":        {"type": "date"},
        }
    }
}


class EffectivenessService:
    def __init__(self, settings: Settings):
        self.settings = settings

    def _client(self, api_key: Optional[str] = None) -> Elasticsearch:
        from config import make_es_client
        return make_es_client(self.settings, api_key, es_cls=Elasticsearch)

    def _ensure_index(self, client: Elasticsearch) -> None:
        try:
            if not client.indices.exists(index=INDEX):
                client.indices.create(index=INDEX, body=MAPPING)
        except ElasticsearchException as e:
            logger.warning(f"Could not ensure {INDEX} index: {e}")

    def _extract_title(self, rule_yaml: str) -> str:
        for line in rule_yaml.splitlines():
            stripped = line.strip()
            if stripped.startswith("title:"):
                return stripped[len("title:"):].strip().strip('"').strip("'") or "unknown"
        return "unknown"

    async def record_test_run(
        self,
        rule_yaml: str,
        test_run_id: str,
        hit_count: int,
        index_pattern: str,
        query_format: str,
        api_key: Optional[str] = None,
    ) -> None:
        client = self._client(api_key)
        try:
            self._ensure_index(client)
            doc = {
                "rule_title":     self._extract_title(rule_yaml),
                "rule_yaml_hash": hashlib.sha256(rule_yaml.encode()).hexdigest()[:16],
                "test_run_id":    test_run_id,
                "hit_count":      hit_count,
                "index_pattern":  index_pattern,
                "query_format":   query_format,
                "ran_at":         datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            client.index(index=INDEX, document=doc)
        except ElasticsearchException as e:
            logger.warning(f"Failed to record test run effectiveness: {e}")
        finally:
            client.close()

    async def get_effectiveness(
        self,
        rule_title: str,
        limit: int = 20,
        api_key: Optional[str] = None,
    ) -> List[dict]:
        client = self._client(api_key)
        try:
            self._ensure_index(client)
            resp = client.search(
                index=INDEX,
                body={
                    "query": {"term": {"rule_title": rule_title}},
                    "sort": [{"ran_at": {"order": "desc"}}],
                    "size": limit,
                },
            )
            return [h["_source"] for h in resp["hits"]["hits"]]
        except (NotFoundError, ElasticsearchException) as e:
            logger.warning(f"Effectiveness query failed: {e}")
            return []
        finally:
            client.close()

    async def get_stale_rules(
        self,
        days: int = 30,
        api_key: Optional[str] = None,
    ) -> List[dict]:
        """
        Returns rules that have been tested at least once but had zero hits
        in the last `days` days, or have not been tested at all in that window.
        """
        client = self._client(api_key)
        cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            self._ensure_index(client)
            # Aggregate: for each rule_title, find max ran_at and max hit_count in window
            resp = client.search(
                index=INDEX,
                body={
                    "size": 0,
                    "query": {"range": {"ran_at": {"gte": cutoff}}},
                    "aggs": {
                        "by_rule": {
                            "terms": {"field": "rule_title", "size": 1000},
                            "aggs": {
                                "max_hits":   {"max": {"field": "hit_count"}},
                                "last_run":   {"max": {"field": "ran_at"}},
                                "total_runs": {"value_count": {"field": "test_run_id"}},
                            },
                        }
                    },
                },
            )
            stale = []
            for bucket in resp["aggregations"]["by_rule"]["buckets"]:
                if bucket["max_hits"]["value"] == 0:
                    stale.append({
                        "rule_title":  bucket["key"],
                        "last_run_at": bucket["last_run"]["value_as_string"],
                        "total_runs":  bucket["total_runs"]["value"],
                        "max_hits_in_window": 0,
                        "stale_days":  days,
                    })
            return stale
        except (NotFoundError, ElasticsearchException) as e:
            logger.warning(f"Stale rules query failed: {e}")
            return []
        finally:
            client.close()

    async def compute_quality_score(
        self,
        rule_yaml: str,
        validation_errors: int = 0,
        validation_warnings: int = 0,
        api_key: Optional[str] = None,
    ) -> dict:
        """
        Composite quality score 0-100.
        Deductions:
          - validation errors:   -20 each (cap -60)
          - validation warnings: -5 each  (cap -15)
          - never tested:        -20
          - last run > 90d ago:  -20, > 30d: -10
          - last run 0 hits:     -10
        """
        score = 100
        reasons = []

        error_deduction = min(validation_errors * 20, 60)
        if error_deduction:
            score -= error_deduction
            reasons.append(f"{validation_errors} validation error(s)")

        warn_deduction = min(validation_warnings * 5, 15)
        if warn_deduction:
            score -= warn_deduction
            reasons.append(f"{validation_warnings} validation warning(s)")

        rule_title = self._extract_title(rule_yaml)
        history = await self.get_effectiveness(rule_title, limit=1, api_key=api_key)

        if not history:
            score -= 20
            reasons.append("never tested")
        else:
            last = history[0]
            last_ran = datetime.strptime(last["ran_at"], "%Y-%m-%dT%H:%M:%SZ")
            age_days = (datetime.utcnow() - last_ran).days
            if age_days > 90:
                score -= 20
                reasons.append(f"last tested {age_days}d ago")
            elif age_days > 30:
                score -= 10
                reasons.append(f"last tested {age_days}d ago")
            if last["hit_count"] == 0:
                score -= 10
                reasons.append("last run returned 0 hits")

        return {
            "rule_title": rule_title,
            "score": max(score, 0),
            "reasons": reasons,
        }
