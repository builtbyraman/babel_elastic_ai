"""
IR Readiness Report service.

Computes phase-by-phase detection coverage for named threat scenarios,
mapping expected ATT&CK techniques and IR lifecycle phases against the
deployed rule library.
"""

from __future__ import annotations

import re
from typing import Any

import yaml

IR_PHASES = [
    "preparation",
    "detection",
    "containment",
    "eradication",
    "recovery",
    "post-incident",
]

PHASE_DESCRIPTIONS = {
    "preparation":   "Pre-attack hardening and threat intelligence ingestion",
    "detection":     "Identifying the attack in progress via alerts and IOCs",
    "containment":   "Stopping lateral spread and C2 communication",
    "eradication":   "Removing persistence, malware, and attacker footholds",
    "recovery":      "Restoring systems and validating integrity",
    "post-incident": "Lessons learned and hardening against recurrence",
}

# Each scenario maps IR phase → list of ATT&CK technique IDs expected for that phase
SCENARIOS: dict[str, dict[str, Any]] = {
    "ransomware": {
        "display_name": "Ransomware",
        "description": "File-encrypting ransomware (LockBit, BlackCat, ALPHV). Covers initial access through encryption and exfil.",
        "phases": {
            "preparation": {
                "techniques": ["T1566", "T1566.001", "T1566.002", "T1195", "T1190"],
                "notes": "Phishing and supply-chain initial access vectors.",
            },
            "detection": {
                "techniques": ["T1059", "T1059.001", "T1059.003", "T1204.002", "T1027", "T1055", "T1218", "T1562"],
                "notes": "Script execution, obfuscation, process injection, and defense evasion.",
            },
            "containment": {
                "techniques": ["T1071", "T1071.001", "T1021", "T1021.001", "T1021.002", "T1041", "T1570"],
                "notes": "C2 channel detection, lateral movement blocking, and exfil monitoring.",
            },
            "eradication": {
                "techniques": ["T1547", "T1547.001", "T1543", "T1543.003", "T1136", "T1053", "T1053.005"],
                "notes": "Persistence mechanisms: registry, services, scheduled tasks, new accounts.",
            },
            "recovery": {
                "techniques": ["T1490", "T1489", "T1529"],
                "notes": "Inhibiting system recovery, stopping services, forced reboots.",
            },
            "post-incident": {
                "techniques": ["T1003", "T1003.001", "T1552", "T1070", "T1070.001"],
                "notes": "Credential theft review and log-clearing for forensic gap analysis.",
            },
        },
    },
    "credential_theft": {
        "display_name": "Credential Theft",
        "description": "Credential harvesting campaign — LSASS dumping, Kerberoasting, Pass-the-Hash.",
        "phases": {
            "preparation": {
                "techniques": ["T1566", "T1566.001", "T1078", "T1133"],
                "notes": "Phishing for initial credential access or valid account abuse.",
            },
            "detection": {
                "techniques": ["T1003", "T1003.001", "T1003.002", "T1110", "T1558", "T1558.003", "T1552"],
                "notes": "LSASS access, SAM dumping, brute force, Kerberoasting.",
            },
            "containment": {
                "techniques": ["T1021", "T1021.001", "T1550", "T1550.002", "T1557"],
                "notes": "Pass-the-Hash, RDP lateral movement, AitM attacks.",
            },
            "eradication": {
                "techniques": ["T1098", "T1136", "T1136.001", "T1136.002"],
                "notes": "Account manipulation and new account creation for persistence.",
            },
            "recovery": {
                "techniques": ["T1078"],
                "notes": "Detection of valid account reuse post-breach.",
            },
            "post-incident": {
                "techniques": ["T1552", "T1552.001"],
                "notes": "Residual unsecured credential review.",
            },
        },
    },
    "lateral_movement": {
        "display_name": "Lateral Movement",
        "description": "Attacker pivoting through the internal network after initial compromise.",
        "phases": {
            "preparation": {
                "techniques": ["T1082", "T1083", "T1057", "T1049", "T1016", "T1135", "T1087"],
                "notes": "Internal discovery: system info, file system, process, network, shares.",
            },
            "detection": {
                "techniques": ["T1021", "T1021.001", "T1021.002", "T1021.006", "T1047", "T1570"],
                "notes": "RDP, SMB, WinRM, WMI, and tool transfer.",
            },
            "containment": {
                "techniques": ["T1550", "T1550.002", "T1557"],
                "notes": "Pass-the-Hash and AitM credential relay.",
            },
            "eradication": {
                "techniques": ["T1547", "T1543", "T1053", "T1505"],
                "notes": "Persistence left behind during pivoting.",
            },
            "recovery": {
                "techniques": ["T1070", "T1070.004"],
                "notes": "Attacker evidence removal during retreat.",
            },
            "post-incident": {
                "techniques": ["T1036", "T1036.005"],
                "notes": "Masquerading used to blend in with legitimate traffic.",
            },
        },
    },
    "insider_threat": {
        "display_name": "Insider Threat",
        "description": "Malicious insider collecting and exfiltrating sensitive data.",
        "phases": {
            "preparation": {
                "techniques": ["T1005", "T1039", "T1083"],
                "notes": "Data collection from local system and network shares.",
            },
            "detection": {
                "techniques": ["T1074", "T1074.001", "T1113", "T1056"],
                "notes": "Data staging, screen capture, input capture.",
            },
            "containment": {
                "techniques": ["T1041", "T1048", "T1048.003", "T1567", "T1567.002"],
                "notes": "Exfiltration over C2, alternative protocols, and web services.",
            },
            "eradication": {
                "techniques": ["T1070", "T1070.004", "T1027"],
                "notes": "Evidence cleanup and obfuscation.",
            },
            "recovery": {
                "techniques": [],
                "notes": "DLP validation and access review (no specific ATT&CK techniques).",
            },
            "post-incident": {
                "techniques": ["T1078"],
                "notes": "Valid account review and privilege audit.",
            },
        },
    },
}

_TAG_TECHNIQUE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def _parse_rule(raw: str) -> dict[str, Any]:
    """Extract title, technique IDs, and x-ir-phase from a rule YAML string."""
    try:
        data = yaml.safe_load(raw)
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    title = str(data.get("title", "Unknown"))
    tags: list[str] = data.get("tags", []) or []
    techniques: list[str] = []
    for tag in tags:
        m = _TAG_TECHNIQUE.match(str(tag).lower())
        if m:
            techniques.append(m.group(1).upper())
    ir_phase = str(data.get("x-ir-phase", "")).strip().lower() or None
    return {"title": title, "techniques": techniques, "ir_phase": ir_phase}


def compute_ir_readiness(scenario_key: str, rule_yamls: list[str]) -> dict[str, Any]:
    """
    Compute IR readiness gap report for a named scenario.

    Returns per-phase coverage including covered/missing techniques and
    whether any rules are explicitly tagged with each IR phase.
    """
    scenario = SCENARIOS.get(scenario_key)
    if scenario is None:
        raise ValueError(f"Unknown scenario: {scenario_key!r}. Valid: {list(SCENARIOS)}")

    # Parse all rules
    parsed_rules = [_parse_rule(y) for y in rule_yamls]
    parsed_rules = [r for r in parsed_rules if r]

    # Build indexes
    technique_to_rules: dict[str, list[str]] = {}
    phase_to_rules: dict[str, list[str]] = {}

    for rule in parsed_rules:
        for tid in rule["techniques"]:
            technique_to_rules.setdefault(tid, [])
            if rule["title"] not in technique_to_rules[tid]:
                technique_to_rules[tid].append(rule["title"])
        if rule["ir_phase"]:
            phase_to_rules.setdefault(rule["ir_phase"], [])
            if rule["title"] not in phase_to_rules[rule["ir_phase"]]:
                phase_to_rules[rule["ir_phase"]].append(rule["title"])

    # Compute per-phase results
    phase_results = []
    total_expected = 0
    total_covered = 0

    for phase in IR_PHASES:
        phase_def = scenario["phases"].get(phase, {"techniques": [], "notes": ""})
        expected_techniques: list[str] = phase_def.get("techniques", [])
        covered = [t for t in expected_techniques if t in technique_to_rules]
        missing = [t for t in expected_techniques if t not in technique_to_rules]

        # Rules covering any expected technique for this phase
        covering_rules: list[str] = []
        for t in covered:
            for r in technique_to_rules.get(t, []):
                if r not in covering_rules:
                    covering_rules.append(r)

        # Rules explicitly tagged with this IR phase
        tagged_rules = phase_to_rules.get(phase, [])

        phase_covered_count = len(covered)
        phase_total_count = len(expected_techniques)
        total_expected += phase_total_count
        total_covered += phase_covered_count

        pct = round(phase_covered_count / phase_total_count * 100) if phase_total_count > 0 else 0

        phase_results.append({
            "phase": phase,
            "description": PHASE_DESCRIPTIONS.get(phase, ""),
            "notes": phase_def.get("notes", ""),
            "expected_techniques": expected_techniques,
            "covered_techniques": covered,
            "missing_techniques": missing,
            "technique_coverage_pct": pct,
            "has_technique_coverage": len(covered) > 0,
            "covering_rules": covering_rules[:10],
            "tagged_rules": tagged_rules[:10],
            "has_tagged_rules": len(tagged_rules) > 0,
            "rule_count": len(set(covering_rules + tagged_rules)),
        })

    overall_pct = round(total_covered / total_expected * 100) if total_expected > 0 else 0
    phases_with_coverage = sum(1 for p in phase_results if p["has_technique_coverage"])

    return {
        "scenario": scenario_key,
        "scenario_display": scenario["display_name"],
        "scenario_description": scenario["description"],
        "total_rules_analyzed": len(parsed_rules),
        "phases": phase_results,
        "phases_covered": phases_with_coverage,
        "phases_total": len(IR_PHASES),
        "overall_technique_coverage_pct": overall_pct,
        "total_expected_techniques": total_expected,
        "total_covered_techniques": total_covered,
        "available_scenarios": {k: v["display_name"] for k, v in SCENARIOS.items()},
    }
