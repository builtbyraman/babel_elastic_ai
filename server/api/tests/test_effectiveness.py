"""
Tests for effectiveness service and routes.
"""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timedelta

from services.effectiveness import EffectivenessService
from config import Settings


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_settings():
    s = MagicMock(spec=Settings)
    s.elasticsearch_url.return_value = "http://localhost:9200"
    return s


def make_effectiveness_hit(rule_title="Test Rule", hit_count=5, days_ago=10):
    ran_at = (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "rule_title":     rule_title,
        "rule_yaml_hash": "abc123",
        "test_run_id":    "run-1",
        "hit_count":      hit_count,
        "index_pattern":  "logs-*",
        "query_format":   "eql",
        "ran_at":         ran_at,
    }


# ── Service: _extract_title ───────────────────────────────────────────────────

def test_extract_title_basic(sample_sigma_rule):
    svc = EffectivenessService(make_settings())
    assert svc._extract_title(sample_sigma_rule) == "Test Rule"


def test_extract_title_titled_rule(titled_sigma_rule):
    svc = EffectivenessService(make_settings())
    assert svc._extract_title(titled_sigma_rule) == "Suspicious PowerShell Execution"


def test_extract_title_missing():
    svc = EffectivenessService(make_settings())
    assert svc._extract_title("detection:\n  condition: selection\n") == "unknown"


def test_extract_title_quoted():
    svc = EffectivenessService(make_settings())
    rule = 'title: "My Quoted Rule"\ndescription: test\n'
    assert svc._extract_title(rule) == "My Quoted Rule"


# ── Service: compute_quality_score ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_quality_score_perfect(mock_es, sample_sigma_rule):
    hit = make_effectiveness_hit(rule_title="Test Rule", hit_count=10, days_ago=5)
    mock_es.search.return_value = {
        "hits": {
            "total": {"value": 1},
            "hits": [{"_id": "id-0", "_source": hit, "_index": "logs-2024"}],
        },
        "aggregations": {},
    }
    svc = EffectivenessService(make_settings())
    result = await svc.compute_quality_score(sample_sigma_rule, 0, 0)
    assert result["score"] == 100
    assert result["reasons"] == []


@pytest.mark.asyncio
async def test_quality_score_never_tested(mock_es, sample_sigma_rule):
    mock_es.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {},
    }
    svc = EffectivenessService(make_settings())
    result = await svc.compute_quality_score(sample_sigma_rule, 0, 0)
    assert result["score"] == 80
    assert "never tested" in result["reasons"]


@pytest.mark.asyncio
async def test_quality_score_validation_errors(mock_es, sample_sigma_rule):
    mock_es.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {},
    }
    svc = EffectivenessService(make_settings())
    result = await svc.compute_quality_score(sample_sigma_rule, validation_errors=2, validation_warnings=1)
    # -40 errors, -5 warning, -20 never tested → 35
    assert result["score"] == 35
    assert any("error" in r for r in result["reasons"])
    assert any("warning" in r for r in result["reasons"])


@pytest.mark.asyncio
async def test_quality_score_error_cap(mock_es, sample_sigma_rule):
    mock_es.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {},
    }
    svc = EffectivenessService(make_settings())
    # 5 errors × 20 = 100, capped at 60; + 20 never tested → 100 - 60 - 20 = 20
    result = await svc.compute_quality_score(sample_sigma_rule, validation_errors=5)
    assert result["score"] == 20


@pytest.mark.asyncio
async def test_quality_score_stale_30d(mock_es, sample_sigma_rule):
    hit = make_effectiveness_hit(rule_title="Test Rule", hit_count=3, days_ago=45)
    mock_es.search.return_value = {
        "hits": {
            "total": {"value": 1},
            "hits": [{"_id": "id-0", "_source": hit, "_index": "logs-2024"}],
        },
        "aggregations": {},
    }
    svc = EffectivenessService(make_settings())
    result = await svc.compute_quality_score(sample_sigma_rule)
    assert result["score"] == 90  # -10 for 30<age<=90d
    assert any("ago" in r for r in result["reasons"])


@pytest.mark.asyncio
async def test_quality_score_stale_90d(mock_es, sample_sigma_rule):
    hit = make_effectiveness_hit(rule_title="Test Rule", hit_count=3, days_ago=100)
    mock_es.search.return_value = {
        "hits": {
            "total": {"value": 1},
            "hits": [{"_id": "id-0", "_source": hit, "_index": "logs-2024"}],
        },
        "aggregations": {},
    }
    svc = EffectivenessService(make_settings())
    result = await svc.compute_quality_score(sample_sigma_rule)
    assert result["score"] == 80  # -20 for >90d


@pytest.mark.asyncio
async def test_quality_score_zero_hits(mock_es, sample_sigma_rule):
    hit = make_effectiveness_hit(rule_title="Test Rule", hit_count=0, days_ago=5)
    mock_es.search.return_value = {
        "hits": {
            "total": {"value": 1},
            "hits": [{"_id": "id-0", "_source": hit, "_index": "logs-2024"}],
        },
        "aggregations": {},
    }
    svc = EffectivenessService(make_settings())
    result = await svc.compute_quality_score(sample_sigma_rule)
    assert result["score"] == 90  # -10 for 0 hits
    assert "0 hits" in result["reasons"][0]


# ── Service: get_stale_rules ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_stale_rules_returns_zero_hit_buckets(mock_es):
    mock_es.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {
            "by_rule": {
                "buckets": [
                    {
                        "key": "Dead Rule",
                        "max_hits": {"value": 0},
                        "last_run": {"value_as_string": "2024-01-01T00:00:00Z"},
                        "total_runs": {"value": 3},
                    },
                    {
                        "key": "Active Rule",
                        "max_hits": {"value": 12},
                        "last_run": {"value_as_string": "2024-01-15T00:00:00Z"},
                        "total_runs": {"value": 5},
                    },
                ]
            }
        },
    }
    svc = EffectivenessService(make_settings())
    stale = await svc.get_stale_rules(days=30)
    assert len(stale) == 1
    assert stale[0]["rule_title"] == "Dead Rule"
    assert stale[0]["max_hits_in_window"] == 0


@pytest.mark.asyncio
async def test_get_stale_rules_empty(mock_es):
    mock_es.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {"by_rule": {"buckets": []}},
    }
    svc = EffectivenessService(make_settings())
    stale = await svc.get_stale_rules(days=30)
    assert stale == []


# ── Routes ────────────────────────────────────────────────────────────────────

def test_get_effectiveness_route(client, auth, mock_es):
    hit = make_effectiveness_hit()
    mock_es.search.return_value = {
        "hits": {
            "total": {"value": 1},
            "hits": [{"_id": "id-0", "_source": hit, "_index": "logs-2024"}],
        },
        "aggregations": {},
    }
    resp = client.get("/v1/rules/effectiveness", params={"rule_title": "Test Rule"}, headers=auth)
    assert resp.status_code == 200
    data = resp.json()
    assert data["rule_title"] == "Test Rule"
    assert len(data["records"]) == 1
    assert data["records"][0]["hit_count"] == 5


def test_get_stale_rules_route(client, auth, mock_es):
    mock_es.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {
            "by_rule": {
                "buckets": [
                    {
                        "key": "Old Rule",
                        "max_hits": {"value": 0},
                        "last_run": {"value_as_string": "2024-01-01T00:00:00Z"},
                        "total_runs": {"value": 2},
                    }
                ]
            }
        },
    }
    resp = client.get("/v1/rules/stale", params={"days": 30}, headers=auth)
    assert resp.status_code == 200
    data = resp.json()
    assert data["days"] == 30
    assert len(data["stale_rules"]) == 1
    assert data["stale_rules"][0]["rule_title"] == "Old Rule"


def test_quality_score_route_never_tested(client, auth, mock_es, sample_sigma_rule):
    mock_es.search.return_value = {
        "hits": {"total": {"value": 0}, "hits": []},
        "aggregations": {},
    }
    resp = client.post(
        "/v1/rules/quality",
        json={"rule_yaml": sample_sigma_rule},
        headers=auth,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["rule_title"] == "Test Rule"
    assert isinstance(data["score"], int)
    assert 0 <= data["score"] <= 100
    assert "never tested" in data["reasons"]


def test_quality_score_route_missing_body(client, auth):
    resp = client.post("/v1/rules/quality", json={}, headers=auth)
    assert resp.status_code == 422
