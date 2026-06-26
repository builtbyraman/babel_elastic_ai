"""
Tests for the SIGMA rule validation service and route.
"""

import pytest
from services.validation import validate_rule


VALID_RULE = """title: Suspicious PowerShell Execution
status: experimental
description: Detects suspicious PowerShell usage via encoded commands
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
    condition: selection
level: high
tags:
    - attack.t1059.001
    - attack.execution
falsepositives:
    - Legitimate admin scripts
"""

YAML_PARSE_ERROR = "title: [unclosed"

MISSING_REQUIRED_FIELDS = """detection:
    condition: selection
"""

NOT_YAML_DICT = "- just a list item"


# ── Service: validate_rule ─────────────────────────────────────────────────────

def test_validate_rule_returns_list():
    issues = validate_rule(VALID_RULE)
    assert isinstance(issues, list)


def test_validate_yaml_parse_error():
    issues = validate_rule(YAML_PARSE_ERROR)
    assert len(issues) == 1
    assert issues[0]["type"] == "error"
    assert "YAML parse error" in issues[0]["message"]
    assert issues[0]["rule"] == "yaml_parse"


def test_validate_not_a_dict():
    issues = validate_rule(NOT_YAML_DICT)
    assert any(i["rule"] == "yaml_structure" for i in issues)


def test_validate_missing_title():
    rule = "status: experimental\nlogsource:\n    category: process_creation\ndetection:\n    condition: selection\n"
    issues = validate_rule(rule)
    assert any("title" in i["message"] for i in issues)
    assert any(i["type"] == "error" for i in issues)


def test_validate_missing_detection():
    rule = "title: Missing Detection\nstatus: experimental\nlogsource:\n    category: process_creation\n"
    issues = validate_rule(rule)
    assert any("detection" in i["message"] for i in issues)


def test_validate_all_required_fields_missing():
    issues = validate_rule(MISSING_REQUIRED_FIELDS)
    missing = [i["message"] for i in issues if "Missing required field" in i["message"]]
    # title, status, logsource are all missing
    assert len(missing) >= 3


def test_validate_valid_rule_has_no_errors(titled_sigma_rule):
    issues = validate_rule(titled_sigma_rule)
    errors = [i for i in issues if i["type"] == "error"]
    # A well-formed rule may have warnings (no date, etc.) but no structural errors
    assert errors == []


def test_validate_issue_structure(titled_sigma_rule):
    issues = validate_rule(titled_sigma_rule)
    for issue in issues:
        assert "type" in issue
        assert issue["type"] in ("error", "warning")
        assert "rule" in issue
        assert "message" in issue


# ── Route: POST /v1/rules/validate ────────────────────────────────────────────

def test_validate_route_valid_rule(client, auth, titled_sigma_rule):
    resp = client.post(
        "/v1/rules/validate",
        json={"rule_yaml": titled_sigma_rule},
        headers=auth,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "valid" in data
    assert "issues" in data
    assert isinstance(data["issues"], list)


def test_validate_route_valid_is_true_for_clean_rule(client, auth):
    resp = client.post(
        "/v1/rules/validate",
        json={"rule_yaml": VALID_RULE},
        headers=auth,
    )
    assert resp.status_code == 200
    data = resp.json()
    errors = [i for i in data["issues"] if i["type"] == "error"]
    if not errors:
        assert data["valid"] is True


def test_validate_route_valid_is_false_for_bad_yaml(client, auth):
    resp = client.post(
        "/v1/rules/validate",
        json={"rule_yaml": YAML_PARSE_ERROR},
        headers=auth,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert len(data["issues"]) > 0


def test_validate_route_requires_rule_yaml(client, auth):
    resp = client.post("/v1/rules/validate", json={}, headers=auth)
    assert resp.status_code == 422


def test_validate_route_requires_auth(client, titled_sigma_rule):
    resp = client.post(
        "/v1/rules/validate",
        json={"rule_yaml": titled_sigma_rule},
    )
    assert resp.status_code == 401


def test_validate_route_missing_fields_returns_errors(client, auth):
    resp = client.post(
        "/v1/rules/validate",
        json={"rule_yaml": MISSING_REQUIRED_FIELDS},
        headers=auth,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    error_messages = [i["message"] for i in data["issues"] if i["type"] == "error"]
    assert any("title" in m or "status" in m or "logsource" in m for m in error_messages)
