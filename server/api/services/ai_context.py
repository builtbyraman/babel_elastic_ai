"""
AI context gathering service.

Before every LLM call we gather live ES context so the model has accurate
field names, types, and sample events — replicating the Agent Builder
tool-access pattern (get_index_mapping + search + get_document_by_id)
without depending on the Kibana Agent Builder runtime.
"""

import logging
from typing import Optional

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError, TransportError as ElasticsearchException

from config import Settings

logger = logging.getLogger(__name__)

# Security Onion alert indices
SO_ALERT_INDICES = ["so-alert-*", "so-logs-*"]

# Kibana security alert index
KIBANA_ALERT_INDEX = ".alerts-security.alerts-default"


def _flatten_mapping(mapping: dict, prefix: str = "") -> dict:
    result = {}
    for field, meta in mapping.get("properties", {}).items():
        full = f"{prefix}.{field}" if prefix else field
        if "type" in meta:
            result[full] = meta["type"]
        if "properties" in meta:
            result.update(_flatten_mapping(meta, full))
    return result


class AIContextService:
    def __init__(self, settings: Settings):
        self.settings = settings

    def _client(self, api_key: Optional[str] = None) -> Elasticsearch:
        from config import make_es_client
        return make_es_client(self.settings, api_key, es_cls=Elasticsearch)

    def _get_mappings(self, client: Elasticsearch, index_pattern: str) -> dict:
        try:
            resp = client.indices.get_mapping(index=index_pattern)
            merged = {}
            for mapping in resp.values():
                merged.update(_flatten_mapping(mapping.get("mappings", {})))
            return merged
        except (NotFoundError, ElasticsearchException):
            return {}

    def _search_matching_events(
        self, client: Elasticsearch, index_pattern: str, ioc_terms: list[dict], size: int = 3
    ) -> list[dict]:
        """Search for events matching IOC terms (used for IOC → rule context)."""
        try:
            body = {
                "size": size,
                "_source": True,
                "query": {
                    "bool": {
                        "should": ioc_terms,
                        "minimum_should_match": 1,
                    }
                },
            }
            resp = client.search(index=index_pattern, body=body)
            return [h["_source"] for h in resp["hits"]["hits"]]
        except ElasticsearchException:
            return []

    async def gather_ioc_context(
        self,
        iocs: list[str],
        index_pattern: str = "logs-*",
        api_key: Optional[str] = None,
    ) -> dict:
        """
        Gather field mappings and sample events for IOC → rule drafting.
        iocs: free-form strings (IPs, hashes, process names, registry keys, etc.)
        """
        client = self._client(api_key)
        try:
            field_mappings = self._get_mappings(client, index_pattern)

            ioc_terms = [
                {"multi_match": {"query": ioc, "fields": ["*"], "type": "phrase"}}
                for ioc in iocs[:5]
            ]
            sample_events = self._search_matching_events(client, index_pattern, ioc_terms)

            return {
                "index_pattern": index_pattern,
                "field_mappings": field_mappings,
                "sample_events": sample_events,
                "iocs": iocs,
            }
        finally:
            client.close()

    async def gather_alert_context(
        self,
        alert_id: str,
        api_key: Optional[str] = None,
    ) -> dict:
        """
        Fetch a Kibana security alert by ID and the field mappings for its index.
        Used for Elastic Alert → SIGMA draft.
        """
        client = self._client(api_key)
        try:
            try:
                doc = client.get(index=KIBANA_ALERT_INDEX, id=alert_id)
                alert_doc = doc["_source"]
                index_used = KIBANA_ALERT_INDEX
            except NotFoundError:
                # Fallback: search across all alert indices
                resp = client.search(
                    index=".alerts-*",
                    body={"query": {"term": {"_id": alert_id}}, "size": 1},
                )
                hits = resp["hits"]["hits"]
                if not hits:
                    return {"error": f"Alert '{alert_id}' not found"}
                alert_doc = hits[0]["_source"]
                index_used = hits[0]["_index"]

            field_mappings = self._get_mappings(client, index_used)
            return {
                "alert_id": alert_id,
                "alert_doc": alert_doc,
                "field_mappings": field_mappings,
                "source_type": "kibana_security",
            }
        except ElasticsearchException as e:
            return {"error": str(e)}
        finally:
            client.close()

    async def gather_so_alert_context(
        self,
        alert_id: str,
        api_key: Optional[str] = None,
    ) -> dict:
        """
        Fetch a Security Onion alert by ID.
        Detects alert type: suricata (has rule.sid) vs sigma (has rule.uuid) vs zeek.
        Used for SO/Suricata → SIGMA draft.
        """
        client = self._client(api_key)
        try:
            resp = client.search(
                index=",".join(SO_ALERT_INDICES),
                body={"query": {"term": {"_id": alert_id}}, "size": 1},
            )
            hits = resp["hits"]["hits"]
            if not hits:
                return {"error": f"SO alert '{alert_id}' not found"}

            alert_doc = hits[0]["_source"]
            index_used = hits[0]["_index"]
            field_mappings = self._get_mappings(client, index_used)

            # Determine alert origin
            rule = alert_doc.get("rule", {})
            if rule.get("sid") or alert_doc.get("event", {}).get("module") == "suricata":
                source_type = "suricata"
            elif rule.get("uuid") or alert_doc.get("event", {}).get("module") == "sigma":
                source_type = "sigma"
            elif alert_doc.get("event", {}).get("module") == "zeek":
                source_type = "zeek"
            else:
                source_type = "unknown"

            return {
                "alert_id": alert_id,
                "alert_doc": alert_doc,
                "field_mappings": field_mappings,
                "source_type": source_type,
            }
        except ElasticsearchException as e:
            return {"error": str(e)}
        finally:
            client.close()

    async def list_recent_alerts(
        self,
        index_pattern: str = ".alerts-security.alerts-default",
        size: int = 20,
        api_key: Optional[str] = None,
    ) -> list[dict]:
        """List recent alerts for the Alert → SIGMA picker UI."""
        client = self._client(api_key)
        try:
            resp = client.search(
                index=index_pattern,
                body={
                    "size": size,
                    "sort": [{"@timestamp": {"order": "desc"}}],
                    "_source": [
                        "_id", "@timestamp",
                        "kibana.alert.rule.name", "kibana.alert.severity",
                        "kibana.alert.rule.category", "host.name",
                        "rule.name", "rule.category", "event.module",
                    ],
                },
            )
            return [
                {"_id": h["_id"], **h["_source"]}
                for h in resp["hits"]["hits"]
            ]
        except (NotFoundError, ElasticsearchException):
            return []
        finally:
            client.close()
