"""
Tests for rule registry service and routes.
"""

import pytest
from unittest.mock import MagicMock
from elasticsearch.exceptions import NotFoundError

from services.rule_registry import RuleRegistryService
from config import Settings


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_settings():
    s = MagicMock(spec=Settings)
    s.elasticsearch_url.return_value = "http://localhost:9200"
    return s


SAMPLE_ID   = "kb-rule-abc-123"
SAMPLE_YAML = "title: Test Rule\ndetection:\n  condition: selection\n"
SAMPLE_TITLE = "Test Rule"


# ── Service: register ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_indexes_document(mock_es):
    svc = RuleRegistryService(make_settings())
    result = await svc.register(SAMPLE_ID, SAMPLE_YAML, SAMPLE_TITLE)
    assert result["kibana_rule_id"] == SAMPLE_ID
    assert "registered_at" in result

    call_kwargs = mock_es.index.call_args[1]
    assert call_kwargs["id"] == SAMPLE_ID
    doc = call_kwargs["document"]
    assert doc["rule_yaml"] == SAMPLE_YAML
    assert doc["title"] == SAMPLE_TITLE
    assert doc["kibana_rule_id"] == SAMPLE_ID


@pytest.mark.asyncio
async def test_register_uses_kibana_id_as_doc_id(mock_es):
    svc = RuleRegistryService(make_settings())
    await svc.register("unique-rule-id", SAMPLE_YAML, SAMPLE_TITLE)
    call_kwargs = mock_es.index.call_args[1]
    assert call_kwargs["id"] == "unique-rule-id"


# ── Service: get_source ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_source_returns_document(mock_es):
    mock_es.get.return_value = {
        "_id": SAMPLE_ID,
        "_source": {
            "kibana_rule_id": SAMPLE_ID,
            "rule_yaml":      SAMPLE_YAML,
            "title":          SAMPLE_TITLE,
            "registered_at":  "2024-01-01T00:00:00Z",
        },
    }
    mock_es.get.side_effect = None  # clear NotFoundError default
    svc = RuleRegistryService(make_settings())
    source = await svc.get_source(SAMPLE_ID)
    assert source is not None
    assert source["kibana_rule_id"] == SAMPLE_ID
    assert source["rule_yaml"] == SAMPLE_YAML


@pytest.mark.asyncio
async def test_get_source_not_found_returns_none(mock_es):
    mock_es.get.side_effect = NotFoundError(404, "not found", {})
    svc = RuleRegistryService(make_settings())
    source = await svc.get_source("nonexistent-id")
    assert source is None


# ── Routes ────────────────────────────────────────────────────────────────────

def test_register_route(client, auth, mock_es):
    mock_es.get.side_effect = None
    mock_es.get.return_value = {
        "_id": SAMPLE_ID,
        "_source": {
            "kibana_rule_id": SAMPLE_ID,
            "rule_yaml":      SAMPLE_YAML,
            "title":          SAMPLE_TITLE,
            "registered_at":  "2024-01-01T00:00:00Z",
        },
    }
    resp = client.post(
        "/v1/rules/register",
        json={
            "kibana_rule_id": SAMPLE_ID,
            "rule_yaml":      SAMPLE_YAML,
            "title":          SAMPLE_TITLE,
        },
        headers=auth,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["kibana_rule_id"] == SAMPLE_ID
    assert "registered_at" in data


def test_register_route_missing_fields(client, auth):
    resp = client.post(
        "/v1/rules/register",
        json={"kibana_rule_id": SAMPLE_ID},  # missing rule_yaml + title
        headers=auth,
    )
    assert resp.status_code == 422


def test_get_source_route_found(client, auth, mock_es):
    mock_es.get.side_effect = None
    mock_es.get.return_value = {
        "_id": SAMPLE_ID,
        "_source": {
            "kibana_rule_id": SAMPLE_ID,
            "rule_yaml":      SAMPLE_YAML,
            "title":          SAMPLE_TITLE,
            "registered_at":  "2024-01-01T00:00:00Z",
        },
    }
    resp = client.get(
        "/v1/rules/source",
        params={"kibana_rule_id": SAMPLE_ID},
        headers=auth,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["kibana_rule_id"] == SAMPLE_ID
    assert data["rule_yaml"] == SAMPLE_YAML


def test_get_source_route_not_found(client, auth, mock_es):
    mock_es.get.side_effect = NotFoundError(404, "not found", {})
    resp = client.get(
        "/v1/rules/source",
        params={"kibana_rule_id": "does-not-exist"},
        headers=auth,
    )
    assert resp.status_code == 404


def test_get_source_route_missing_param(client, auth):
    resp = client.get("/v1/rules/source", headers=auth)
    assert resp.status_code == 422
