"""
Rule registry service.

Persists the original Sigma YAML for every rule deployed via sigma_ai,
keyed by Kibana detection rule ID. Enables alert → SIGMA reverse lookup.
"""

import logging
from datetime import datetime
from typing import Optional

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError, TransportError as ElasticsearchException

from config import Settings

logger = logging.getLogger(__name__)

INDEX = ".sigma-rule-registry"

MAPPING = {
    "mappings": {
        "properties": {
            "kibana_rule_id": {"type": "keyword"},
            "title":          {"type": "keyword"},
            "rule_yaml":      {"type": "text", "index": False},
            "registered_at":  {"type": "date"},
        }
    }
}


class RuleRegistryService:
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

    async def register(
        self,
        kibana_rule_id: str,
        rule_yaml: str,
        title: str,
        api_key: Optional[str] = None,
    ) -> dict:
        client = self._client(api_key)
        try:
            self._ensure_index(client)
            now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            doc = {
                "kibana_rule_id": kibana_rule_id,
                "title":          title,
                "rule_yaml":      rule_yaml,
                "registered_at":  now,
            }
            # Use Kibana rule ID as ES doc ID for O(1) retrieval
            client.index(index=INDEX, id=kibana_rule_id, document=doc)
            return {"kibana_rule_id": kibana_rule_id, "registered_at": now}
        finally:
            client.close()

    async def get_source(
        self,
        kibana_rule_id: str,
        api_key: Optional[str] = None,
    ) -> Optional[dict]:
        client = self._client(api_key)
        try:
            self._ensure_index(client)
            doc = client.get(index=INDEX, id=kibana_rule_id)
            return doc["_source"]
        except NotFoundError:
            return None
        except ElasticsearchException as e:
            logger.warning(f"Registry lookup failed for {kibana_rule_id}: {e}")
            return None
        finally:
            client.close()
