"""
Tests for ATT&CK coverage computation service and route.
"""

import pytest
from services.coverage import compute_coverage, TACTICS, TECHNIQUE_NAMES


# ── Fixtures ──────────────────────────────────────────────────────────────────

RULE_WITH_TECHNIQUE = """title: PowerShell Encoded
status: experimental
description: Detects encoded PowerShell
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '-EncodedCommand'
    condition: selection
level: high
tags:
    - attack.t1059.001
    - attack.execution
"""

RULE_WITH_MULTIPLE_TECHNIQUES = """title: Credential Dump
status: experimental
description: Detects LSASS credential dumping
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: 'mimikatz.exe'
    condition: selection
level: critical
tags:
    - attack.t1003.001
    - attack.t1078
    - attack.credential_access
"""

RULE_NO_TAGS = """title: No Tags Rule
status: experimental
description: A rule with no ATT&CK tags
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'suspicious'
    condition: selection
"""

RULE_INVALID_YAML = "title: [broken"

RULE_UNKNOWN_TECHNIQUE = """title: Unknown Technique
status: experimental
description: References a technique not in the lookup
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'x'
    condition: selection
tags:
    - attack.t9999
"""


# ── Service: compute_coverage ─────────────────────────────────────────────────

def test_compute_coverage_empty():
    result = compute_coverage([])
    assert result["total_rules"] == 0
    assert result["parsed_rules"] == 0
    assert result["covered_techniques"] == 0
    assert result["covered_tactics"] == []
    assert result["techniques"] == []
    assert len(result["uncovered_tactics"]) == len(TACTICS)


def test_compute_coverage_single_technique():
    result = compute_coverage([RULE_WITH_TECHNIQUE])
    assert result["total_rules"] == 1
    assert result["parsed_rules"] == 1
    assert result["covered_techniques"] >= 1
    assert "T1059.001" in [t["id"] for t in result["techniques"]]
    assert "execution" in result["covered_tactics"]


def test_compute_coverage_tactic_tag_only():
    rule = "title: X\nstatus: experimental\ndescription: d\nlogsource:\n    category: process_creation\ndetection:\n    condition: selection\ntags:\n    - attack.persistence\n"
    result = compute_coverage([rule])
    assert "persistence" in result["covered_tactics"]


def test_compute_coverage_multiple_rules():
    result = compute_coverage([RULE_WITH_TECHNIQUE, RULE_WITH_MULTIPLE_TECHNIQUES])
    assert result["total_rules"] == 2
    assert result["parsed_rules"] == 2
    technique_ids = [t["id"] for t in result["techniques"]]
    assert "T1059.001" in technique_ids
    assert "T1003.001" in technique_ids
    assert "T1078" in technique_ids


def test_compute_coverage_no_tags_rule():
    result = compute_coverage([RULE_NO_TAGS])
    assert result["parsed_rules"] == 1
    assert result["covered_techniques"] == 0
    assert result["covered_tactics"] == []


def test_compute_coverage_skips_invalid_yaml():
    result = compute_coverage([RULE_INVALID_YAML, RULE_WITH_TECHNIQUE])
    assert result["total_rules"] == 2
    assert result["parsed_rules"] == 1  # only the valid one


def test_compute_coverage_unknown_technique():
    result = compute_coverage([RULE_UNKNOWN_TECHNIQUE])
    technique_ids = [t["id"] for t in result["techniques"]]
    assert "T9999" in technique_ids
    # Unknown technique gets tactic "unknown"
    t = next(t for t in result["techniques"] if t["id"] == "T9999")
    assert t["tactic"] == "unknown"


def test_compute_coverage_by_tactic_grouping():
    result = compute_coverage([RULE_WITH_MULTIPLE_TECHNIQUES])
    by_tactic = result["by_tactic"]
    assert "credential_access" in by_tactic
    assert "T1003.001" in by_tactic["credential_access"]


def test_compute_coverage_rule_index():
    result = compute_coverage([RULE_WITH_TECHNIQUE])
    rule_index = result["rule_index"]
    assert "PowerShell Encoded" in rule_index
    assert "T1059.001" in rule_index["PowerShell Encoded"]


def test_compute_coverage_deduplicates_techniques():
    # Two rules both tag T1059.001; technique should appear once in techniques list
    result = compute_coverage([RULE_WITH_TECHNIQUE, RULE_WITH_TECHNIQUE])
    t1059_entries = [t for t in result["techniques"] if t["id"] == "T1059.001"]
    assert len(t1059_entries) == 1
    # But the rule title appears in the technique's rules list once (deduped)
    assert t1059_entries[0]["rules"].count("PowerShell Encoded") == 1


def test_compute_coverage_uncovered_tactics():
    result = compute_coverage([RULE_WITH_TECHNIQUE])
    uncovered = result["uncovered_tactics"]
    assert "execution" not in uncovered
    assert "reconnaissance" in uncovered


def test_compute_coverage_technique_name_resolved():
    result = compute_coverage([RULE_WITH_TECHNIQUE])
    t = next(t for t in result["techniques"] if t["id"] == "T1059.001")
    assert t["name"] == "PowerShell"
    assert t["tactic_display"] == "Execution"


def test_compute_coverage_case_insensitive_tags():
    rule = """title: Case Test
status: experimental
description: d
logsource:
    category: process_creation
detection:
    condition: selection
tags:
    - attack.T1059.001
"""
    result = compute_coverage([rule])
    assert "T1059.001" in [t["id"] for t in result["techniques"]]


# ── Route: POST /v1/coverage ──────────────────────────────────────────────────

def test_coverage_route_basic(client, auth):
    resp = client.post(
        "/v1/coverage",
        json={"rule_yamls": [RULE_WITH_TECHNIQUE]},
        headers=auth,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "covered_techniques" in data
    assert "covered_tactics" in data
    assert "techniques" in data
    assert "by_tactic" in data
    assert "uncovered_tactics" in data
    assert "rule_index" in data


def test_coverage_route_empty_list(client, auth):
    resp = client.post(
        "/v1/coverage",
        json={"rule_yamls": []},
        headers=auth,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_rules"] == 0
    assert data["covered_techniques"] == 0


def test_coverage_route_multiple_rules(client, auth):
    resp = client.post(
        "/v1/coverage",
        json={"rule_yamls": [RULE_WITH_TECHNIQUE, RULE_WITH_MULTIPLE_TECHNIQUES]},
        headers=auth,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["parsed_rules"] == 2
    assert data["covered_techniques"] >= 3


def test_coverage_route_requires_rule_yamls(client, auth):
    resp = client.post("/v1/coverage", json={}, headers=auth)
    assert resp.status_code == 422


def test_coverage_route_requires_auth(client):
    resp = client.post(
        "/v1/coverage",
        json={"rule_yamls": [RULE_WITH_TECHNIQUE]},
    )
    assert resp.status_code == 401
