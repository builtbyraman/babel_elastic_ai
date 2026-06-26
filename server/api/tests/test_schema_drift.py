"""
Tests for schema drift detection service and routes.
"""

import pytest
from unittest.mock import MagicMock
from elasticsearch.exceptions import NotFoundError

from services.schema_drift import SchemaDriftService, _flatten_mapping, SO_INDEX_PATTERNS
from config import Settings


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_settings():
    s = MagicMock(spec=Settings)
    s.elasticsearch_url.return_value = "http://localhost:9200"
    return s


def make_snapshot_source(fields=None, index_pattern="logs-*"):
    return {
        "index_pattern":  index_pattern,
        "snapshotted_at": "2024-01-01T00:00:00Z",
        "fields":         fields or {"process.name": "keyword", "@timestamp": "date"},
    }


# ── Unit: _flatten_mapping ────────────────────────────────────────────────────

def test_flatten_mapping_flat():
    mapping = {"properties": {"host": {"type": "keyword"}}}
    assert _flatten_mapping(mapping) == {"host": "keyword"}


def test_flatten_mapping_nested():
    mapping = {
        "properties": {
            "process": {
                "properties": {
                    "name": {"type": "keyword"},
                    "pid":  {"type": "long"},
                }
            }
        }
    }
    result = _flatten_mapping(mapping)
    assert result == {"process.name": "keyword", "process.pid": "long"}


def test_flatten_mapping_deeply_nested():
    mapping = {
        "properties": {
            "a": {
                "properties": {
                    "b": {
                        "properties": {
                            "c": {"type": "text"}
                        }
                    }
                }
            }
        }
    }
    result = _flatten_mapping(mapping)
    assert result == {"a.b.c": "text"}


def test_flatten_mapping_empty():
    assert _flatten_mapping({}) == {}
    assert _flatten_mapping({"properties": {}}) == {}


# ── Service: snapshot ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_snapshot_stores_doc(mock_es):
    svc = SchemaDriftService(make_settings())
    result = await svc.snapshot("logs-*")
    assert result["index_pattern"] == "logs-*"
    assert "snapshotted_at" in result
    assert "field_count" in result
    mock_es.index.assert_called_once()


@pytest.mark.asyncio
async def test_snapshot_doc_id_uses_star_replacement(mock_es):
    svc = SchemaDriftService(make_settings())
    await svc.snapshot("so-alert-*")
    call_kwargs = mock_es.index.call_args
    assert call_kwargs[1]["id"] == "so-alert-_star_"


# ── Service: detect_drift ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detect_drift_no_snapshot(mock_es):
    from elasticsearch.exceptions import NotFoundError
    mock_es.get.side_effect = NotFoundError(404, "not found", {})
    svc = SchemaDriftService(make_settings())
    result = await svc.detect_drift("logs-*")
    assert result["drifted_fields"] == []
    assert "No snapshot found" in result["message"]
    assert result["snapshot_taken_at"] is None


@pytest.mark.asyncio
async def test_detect_drift_no_changes(mock_es):
    snapshot_fields = {"process.name": "keyword", "@timestamp": "date"}
    mock_es.get.return_value = {
        "_id": "logs-_star_",
        "_source": make_snapshot_source(snapshot_fields),
    }
    mock_es.get.side_effect = None  # clear the default NotFoundError
    # Live mapping matches snapshot fields
    mock_es.indices.get_mapping.return_value = {
        "logs-2024.01.01": {
            "mappings": {
                "properties": {
                    "process": {"properties": {"name": {"type": "keyword"}}},
                    "@timestamp": {"type": "date"},
                }
            }
        }
    }
    svc = SchemaDriftService(make_settings())
    result = await svc.detect_drift("logs-*")
    assert result["drifted_fields"] == []
    assert result["total_fields_snapshot"] == 2


@pytest.mark.asyncio
async def test_detect_drift_removed_field(mock_es):
    snapshot_fields = {
        "process.name":        "keyword",
        "process.command_line": "text",
        "@timestamp":          "date",
    }
    mock_es.get.return_value = {
        "_id": "logs-_star_",
        "_source": make_snapshot_source(snapshot_fields),
    }
    mock_es.get.side_effect = None
    # Live mapping is missing process.command_line
    mock_es.indices.get_mapping.return_value = {
        "logs-2024.01.01": {
            "mappings": {
                "properties": {
                    "process": {"properties": {"name": {"type": "keyword"}}},
                    "@timestamp": {"type": "date"},
                }
            }
        }
    }
    svc = SchemaDriftService(make_settings())
    result = await svc.detect_drift("logs-*")
    drifted = result["drifted_fields"]
    assert len(drifted) == 1
    assert drifted[0]["field"] == "process.command_line"
    assert drifted[0]["status"] == "removed"
    assert drifted[0]["current_type"] is None


@pytest.mark.asyncio
async def test_detect_drift_type_changed(mock_es):
    snapshot_fields = {"event.code": "keyword"}
    mock_es.get.return_value = {
        "_id": "logs-_star_",
        "_source": make_snapshot_source(snapshot_fields),
    }
    mock_es.get.side_effect = None
    # Live mapping has event.code as integer now
    mock_es.indices.get_mapping.return_value = {
        "logs-2024.01.01": {
            "mappings": {
                "properties": {
                    "event": {"properties": {"code": {"type": "integer"}}},
                }
            }
        }
    }
    svc = SchemaDriftService(make_settings())
    result = await svc.detect_drift("logs-*")
    drifted = result["drifted_fields"]
    assert len(drifted) == 1
    assert drifted[0]["field"] == "event.code"
    assert drifted[0]["status"] == "type_changed"
    assert drifted[0]["previous_type"] == "keyword"
    assert drifted[0]["current_type"] == "integer"


# ── Service: snapshot_all_so ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_snapshot_all_so_calls_each_pattern(mock_es):
    svc = SchemaDriftService(make_settings())
    results = await svc.snapshot_all_so()
    assert len(results) == len(SO_INDEX_PATTERNS)
    for r in results:
        assert "index_pattern" in r
        assert r["index_pattern"] in SO_INDEX_PATTERNS


# ── Routes ────────────────────────────────────────────────────────────────────

def test_snapshot_route(client, auth, mock_es):
    resp = client.post(
        "/v1/schema-drift/snapshot",
        json={"index_pattern": "logs-*"},
        headers=auth,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["index_pattern"] == "logs-*"
    assert "snapshotted_at" in data
    assert "field_count" in data


def test_snapshot_so_route(client, auth, mock_es):
    resp = client.post("/v1/schema-drift/snapshot/so", headers=auth)
    assert resp.status_code == 200
    data = resp.json()
    # Route returns {"results": [...]}
    results = data.get("results", data) if isinstance(data, dict) else data
    assert isinstance(results, list)
    assert len(results) == len(SO_INDEX_PATTERNS)


def test_drift_report_route_no_snapshot(client, auth, mock_es):
    mock_es.get.side_effect = NotFoundError(404, "not found", {})
    resp = client.get(
        "/v1/schema-drift/report",
        params={"index_pattern": "logs-*"},
        headers=auth,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["drifted_fields"] == []
    assert data["snapshot_taken_at"] is None


def test_drift_report_route_missing_param(client, auth):
    resp = client.get("/v1/schema-drift/report", headers=auth)
    assert resp.status_code == 422
