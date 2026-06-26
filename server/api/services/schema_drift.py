"""
Schema drift detection service.

Snapshots ES field mappings for watched index patterns and detects when
fields disappear or change type — both for standard ECS indices and
Security Onion indices (so-alert-*, so-logs-*).
"""

import logging
from datetime import datetime
from typing import Optional, Dict, Any

from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError, TransportError as ElasticsearchException

from config import Settings

logger = logging.getLogger(__name__)

SNAPSHOT_INDEX = ".sigma-schema-snapshots"

SNAPSHOT_MAPPING = {
    "mappings": {
        "properties": {
            "index_pattern":    {"type": "keyword"},
            "snapshotted_at":   {"type": "date"},
            "fields":           {"type": "object", "enabled": False},
        }
    }
}

# Known Security Onion index patterns to auto-include
SO_INDEX_PATTERNS = ["so-alert-*", "so-logs-*", "so-import-*"]


def _flatten_mapping(mapping: Dict[str, Any], prefix: str = "") -> Dict[str, str]:
    """Recursively flatten ES mapping properties into {field_path: type}."""
    result: Dict[str, str] = {}
    props = mapping.get("properties", {})
    for field, meta in props.items():
        full = f"{prefix}{field}" if not prefix else f"{prefix}.{field}"
        if "type" in meta:
            result[full] = meta["type"]
        if "properties" in meta:
            result.update(_flatten_mapping(meta, full))
    return result


class SchemaDriftService:
    def __init__(self, settings: Settings):
        self.settings = settings

    def _client(self, api_key: Optional[str] = None) -> Elasticsearch:
        from config import make_es_client
        return make_es_client(self.settings, api_key, es_cls=Elasticsearch)

    def _ensure_index(self, client: Elasticsearch) -> None:
        try:
            if not client.indices.exists(index=SNAPSHOT_INDEX):
                client.indices.create(index=SNAPSHOT_INDEX, body=SNAPSHOT_MAPPING)
        except ElasticsearchException as e:
            logger.warning(f"Could not ensure {SNAPSHOT_INDEX} index: {e}")

    def _fetch_live_fields(self, client: Elasticsearch, index_pattern: str) -> Dict[str, str]:
        try:
            resp = client.indices.get_mapping(index=index_pattern)
            merged: Dict[str, str] = {}
            for _idx, mapping in resp.items():
                merged.update(_flatten_mapping(mapping.get("mappings", {})))
            return merged
        except (NotFoundError, ElasticsearchException) as e:
            logger.warning(f"Could not fetch mapping for {index_pattern}: {e}")
            return {}

    async def snapshot(
        self,
        index_pattern: str,
        api_key: Optional[str] = None,
    ) -> dict:
        """Store a snapshot of the current field mapping for an index pattern."""
        client = self._client(api_key)
        try:
            self._ensure_index(client)
            fields = self._fetch_live_fields(client, index_pattern)
            now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            doc = {
                "index_pattern":  index_pattern,
                "snapshotted_at": now,
                "fields":         fields,
            }
            # Use index_pattern as doc ID so each pattern has one snapshot (latest wins)
            client.index(
                index=SNAPSHOT_INDEX,
                id=index_pattern.replace("*", "_star_"),
                document=doc,
            )
            return {"index_pattern": index_pattern, "snapshotted_at": now, "field_count": len(fields)}
        finally:
            client.close()

    async def detect_drift(
        self,
        index_pattern: str,
        api_key: Optional[str] = None,
    ) -> dict:
        """Compare current mapping against the stored snapshot."""
        client = self._client(api_key)
        now = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            self._ensure_index(client)
            doc_id = index_pattern.replace("*", "_star_")
            try:
                snap_doc = client.get(index=SNAPSHOT_INDEX, id=doc_id)
                snapshot_fields: Dict[str, str] = snap_doc["_source"]["fields"]
                snapshot_taken_at: str = snap_doc["_source"]["snapshotted_at"]
            except NotFoundError:
                return {
                    "index_pattern":       index_pattern,
                    "snapshot_taken_at":   None,
                    "checked_at":          now,
                    "drifted_fields":      [],
                    "total_fields_snapshot": 0,
                    "total_fields_current":  0,
                    "message":             "No snapshot found. Run /snapshot first.",
                }

            current_fields = self._fetch_live_fields(client, index_pattern)
            drifted = []

            for field, prev_type in snapshot_fields.items():
                if field not in current_fields:
                    drifted.append({
                        "field":         field,
                        "status":        "removed",
                        "previous_type": prev_type,
                        "current_type":  None,
                    })
                elif current_fields[field] != prev_type:
                    drifted.append({
                        "field":         field,
                        "status":        "type_changed",
                        "previous_type": prev_type,
                        "current_type":  current_fields[field],
                    })

            return {
                "index_pattern":         index_pattern,
                "snapshot_taken_at":     snapshot_taken_at,
                "checked_at":            now,
                "drifted_fields":        drifted,
                "total_fields_snapshot": len(snapshot_fields),
                "total_fields_current":  len(current_fields),
            }
        finally:
            client.close()

    async def snapshot_all_so(self, api_key: Optional[str] = None) -> list:
        """Convenience: snapshot all known Security Onion index patterns."""
        results = []
        for pattern in SO_INDEX_PATTERNS:
            try:
                result = await self.snapshot(pattern, api_key=api_key)
                results.append(result)
            except Exception as e:
                results.append({"index_pattern": pattern, "error": str(e)})
        return results
