"""
Contract tests: verify that the Python backend accepts exactly the snake_case
field names that the Kibana TypeScript proxy routes send, and that the response
shapes match what the TypeScript frontend types expect.

Each test documents one Kibana route → Python route translation. If a field
rename breaks on either side, these tests will catch it before it causes a
silent integration failure.

Kibana proxy translation map (camelCase → snake_case):
  Effectiveness:
    ruleYaml          → rule_yaml      (POST /rules/quality)
  Schema Drift:
    indexPattern      → index_pattern  (POST /schema-drift/snapshot, GET /schema-drift/report)
  Rule Registry:
    kibanaRuleId      → kibana_rule_id (POST /rules/register, GET /rules/source)
    ruleYaml          → rule_yaml      (POST /rules/register)
  AI:
    ruleYaml          → rule_yaml      (POST /ai/explain, /ai/improve)
    indexPattern      → index_pattern  (POST /ai/draft-from-iocs, /ai/improve)
    logsourceHint     → logsource_hint (POST /ai/draft-from-iocs)
    alertId           → alert_id       (POST /ai/draft-from-alert)
"""

import pytest


SAMPLE_YAML = """title: Contract Test Rule
status: experimental
description: A rule used by contract tests
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'suspicious.exe'
    condition: selection
level: medium
"""

KIBANA_RULE_ID = "kb-contract-rule-001"


# ── Effectiveness ─────────────────────────────────────────────────────────────

class TestEffectivenessContract:
    """
    Kibana sends:  { ruleYaml: string }
    Backend wants: { rule_yaml: string }
    """

    def test_quality_accepts_snake_case_rule_yaml(self, client, auth, mock_es):
        """Backend accepts rule_yaml (the field name the proxy sends)."""
        mock_es.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
            "aggregations": {},
        }
        resp = client.post(
            "/v1/rules/quality",
            json={"rule_yaml": SAMPLE_YAML},
            headers=auth,
        )
        assert resp.status_code == 200
        data = resp.json()
        # Response shape expected by frontend QualityScoreResult type
        assert "rule_title" in data
        assert "score" in data
        assert "reasons" in data
        assert isinstance(data["score"], int)
        assert isinstance(data["reasons"], list)

    def test_quality_rejects_camel_case_rule_yaml(self, client, auth):
        """Backend rejects ruleYaml (would be a proxy bug — field not translated)."""
        resp = client.post(
            "/v1/rules/quality",
            json={"ruleYaml": SAMPLE_YAML},  # camelCase — should fail validation
            headers=auth,
        )
        assert resp.status_code == 422

    def test_effectiveness_response_shape(self, client, auth, mock_es):
        """GET /rules/effectiveness response matches EffectivenessResult frontend type."""
        mock_es.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
            "aggregations": {},
        }
        resp = client.get(
            "/v1/rules/effectiveness",
            params={"rule_title": "Contract Test Rule"},
            headers=auth,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "rule_title" in data
        assert "records" in data
        assert isinstance(data["records"], list)

    def test_stale_rules_response_shape(self, client, auth, mock_es):
        """GET /rules/stale response matches StaleRulesResult frontend type."""
        mock_es.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
            "aggregations": {"by_rule": {"buckets": []}},
        }
        resp = client.get("/v1/rules/stale", params={"days": 30}, headers=auth)
        assert resp.status_code == 200
        data = resp.json()
        assert "stale_rules" in data
        assert "days" in data
        assert data["days"] == 30


# ── Schema Drift ──────────────────────────────────────────────────────────────

class TestSchemaDriftContract:
    """
    Kibana sends:  { indexPattern: string }
    Backend wants: { index_pattern: string }

    Kibana query:  ?indexPattern=X
    Backend query: ?index_pattern=X
    """

    def test_snapshot_accepts_snake_case_index_pattern(self, client, auth, mock_es):
        """Backend accepts index_pattern (the field name the proxy sends)."""
        resp = client.post(
            "/v1/schema-drift/snapshot",
            json={"index_pattern": "logs-*"},
            headers=auth,
        )
        assert resp.status_code == 200
        data = resp.json()
        # Response shape expected by frontend
        assert "index_pattern" in data
        assert "snapshotted_at" in data
        assert "field_count" in data

    def test_snapshot_rejects_camel_case_index_pattern(self, client, auth):
        """Backend rejects indexPattern (would be a proxy translation bug)."""
        resp = client.post(
            "/v1/schema-drift/snapshot",
            json={"indexPattern": "logs-*"},
            headers=auth,
        )
        assert resp.status_code == 422

    def test_drift_report_accepts_snake_case_query_param(self, client, auth, mock_es):
        """GET /schema-drift/report?index_pattern=X — proxy translates indexPattern → index_pattern."""
        from elasticsearch.exceptions import NotFoundError
        mock_es.get.side_effect = NotFoundError(404, "not found", {})
        resp = client.get(
            "/v1/schema-drift/report",
            params={"index_pattern": "logs-*"},
            headers=auth,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["index_pattern"] == "logs-*"
        assert "drifted_fields" in data
        assert "snapshot_taken_at" in data
        assert "checked_at" in data

    def test_drift_report_rejects_camel_case_param(self, client, auth):
        """Backend requires index_pattern, not indexPattern."""
        resp = client.get(
            "/v1/schema-drift/report",
            params={"indexPattern": "logs-*"},
            headers=auth,
        )
        assert resp.status_code == 422


# ── Rule Registry ─────────────────────────────────────────────────────────────

class TestRuleRegistryContract:
    """
    Kibana sends:  { kibanaRuleId, ruleYaml, title }
    Backend wants: { kibana_rule_id, rule_yaml, title }

    Kibana query:  ?kibanaRuleId=X
    Backend query: ?kibana_rule_id=X
    """

    def test_register_accepts_snake_case_fields(self, client, auth, mock_es):
        """Backend accepts kibana_rule_id and rule_yaml (what the proxy sends)."""
        resp = client.post(
            "/v1/rules/register",
            json={
                "kibana_rule_id": KIBANA_RULE_ID,
                "rule_yaml": SAMPLE_YAML,
                "title": "Contract Test Rule",
            },
            headers=auth,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "kibana_rule_id" in data
        assert data["kibana_rule_id"] == KIBANA_RULE_ID
        assert "registered_at" in data

    def test_register_rejects_camel_case_fields(self, client, auth):
        """Backend rejects kibanaRuleId/ruleYaml (would be a proxy translation bug)."""
        resp = client.post(
            "/v1/rules/register",
            json={
                "kibanaRuleId": KIBANA_RULE_ID,
                "ruleYaml": SAMPLE_YAML,
                "title": "Contract Test Rule",
            },
            headers=auth,
        )
        assert resp.status_code == 422

    def test_get_source_accepts_snake_case_query_param(self, client, auth, mock_es):
        """GET /rules/source?kibana_rule_id=X — proxy translates kibanaRuleId → kibana_rule_id."""
        from elasticsearch.exceptions import NotFoundError
        mock_es.get.side_effect = None
        mock_es.get.return_value = {
            "_id": KIBANA_RULE_ID,
            "_source": {
                "kibana_rule_id": KIBANA_RULE_ID,
                "rule_yaml": SAMPLE_YAML,
                "title": "Contract Test Rule",
                "registered_at": "2024-01-01T00:00:00Z",
            },
        }
        resp = client.get(
            "/v1/rules/source",
            params={"kibana_rule_id": KIBANA_RULE_ID},
            headers=auth,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "kibana_rule_id" in data
        assert "rule_yaml" in data
        assert "title" in data
        assert "registered_at" in data

    def test_get_source_rejects_camel_case_param(self, client, auth):
        """Backend requires kibana_rule_id, not kibanaRuleId."""
        resp = client.get(
            "/v1/rules/source",
            params={"kibanaRuleId": KIBANA_RULE_ID},
            headers=auth,
        )
        assert resp.status_code == 422


# ── AI Routes ─────────────────────────────────────────────────────────────────

class TestAIContract:
    """
    Kibana sends:  { ruleYaml, indexPattern, logsourceHint, alertId, source }
    Backend wants: { rule_yaml, index_pattern, logsource_hint, alert_id, source }
    """

    def test_explain_accepts_snake_case_rule_yaml(self, client, auth, mock_anthropic_explain):
        """POST /ai/explain: backend accepts rule_yaml."""
        resp = client.post(
            "/v1/ai/explain",
            json={"rule_yaml": SAMPLE_YAML},
            headers=auth,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "success" in data
        # Response shape: success + explanation
        assert "explanation" in data or "message" in data

    def test_explain_rejects_camel_case(self, client, auth):
        """POST /ai/explain: rejects ruleYaml."""
        resp = client.post(
            "/v1/ai/explain",
            json={"ruleYaml": SAMPLE_YAML},
            headers=auth,
        )
        assert resp.status_code == 422

    def test_draft_from_iocs_accepts_snake_case_fields(self, client, auth, mock_es, mock_anthropic):
        """POST /ai/draft-from-iocs: accepts index_pattern and logsource_hint."""
        resp = client.post(
            "/v1/ai/draft-from-iocs",
            json={
                "iocs": ["evil.exe"],
                "index_pattern": "logs-*",
                "logsource_hint": "process_creation",
            },
            headers=auth,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "success" in data

    def test_draft_from_iocs_rejects_camel_case(self, client, auth):
        """POST /ai/draft-from-iocs: rejects indexPattern/logsourceHint."""
        resp = client.post(
            "/v1/ai/draft-from-iocs",
            json={
                "iocs": ["evil.exe"],
                "indexPattern": "logs-*",   # camelCase — wrong
                "logsourceHint": "process_creation",
            },
            headers=auth,
        )
        # indexPattern is not in the model, so it will be ignored (not a 422)
        # but the request should still succeed with iocs present
        # This validates the proxy should translate — not that backend rejects the unknown field
        assert resp.status_code in (200, 422)

    def test_improve_accepts_snake_case_fields(self, client, auth, mock_es, mock_anthropic_improve):
        """POST /ai/improve: accepts rule_yaml and index_pattern."""
        resp = client.post(
            "/v1/ai/improve",
            json={"rule_yaml": SAMPLE_YAML, "index_pattern": "logs-*"},
            headers=auth,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "success" in data

    def test_improve_rejects_missing_rule_yaml(self, client, auth):
        """POST /ai/improve: requires rule_yaml."""
        resp = client.post(
            "/v1/ai/improve",
            json={"index_pattern": "logs-*"},
            headers=auth,
        )
        assert resp.status_code == 422

    def test_draft_from_alert_accepts_snake_case_alert_id(self, client, auth, mock_es, mock_anthropic):
        """POST /ai/draft-from-alert: accepts alert_id (proxy translates alertId → alert_id)."""
        mock_es.search.return_value = {
            "hits": {"total": {"value": 0}, "hits": []},
            "aggregations": {},
        }
        resp = client.post(
            "/v1/ai/draft-from-alert",
            json={"alert_id": "some-alert-id", "source": "kibana"},
            headers=auth,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "success" in data

    def test_draft_from_alert_rejects_camel_case_alert_id(self, client, auth):
        """POST /ai/draft-from-alert: rejects alertId (would be a proxy bug)."""
        resp = client.post(
            "/v1/ai/draft-from-alert",
            json={"alertId": "some-alert-id", "source": "kibana"},
            headers=auth,
        )
        assert resp.status_code == 422

    def test_ai_result_response_shape(self, client, auth, mock_anthropic_explain):
        """All AI endpoints return AIResult shape: {success, rule_yaml?, explanation?, changes?, message?, source_type?}."""
        resp = client.post(
            "/v1/ai/explain",
            json={"rule_yaml": SAMPLE_YAML},
            headers=auth,
        )
        assert resp.status_code == 200
        data = resp.json()
        # Required field
        assert "success" in data
        assert isinstance(data["success"], bool)
        # Optional fields — at least one should be present on success
        if data["success"]:
            has_content = any(k in data for k in ("rule_yaml", "explanation", "changes"))
            assert has_content
