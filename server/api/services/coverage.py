"""
Live ATT&CK coverage computation.

Parses Sigma rule YAMLs, extracts attack.t{id} and attack.{tactic} tags,
and returns a structured coverage report against the MITRE ATT&CK matrix.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ── ATT&CK tactic registry ────────────────────────────────────────────────────

TACTICS: dict[str, str] = {
    "reconnaissance":       "Reconnaissance",
    "resource_development": "Resource Development",
    "initial_access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion":      "Defense Evasion",
    "credential_access":    "Credential Access",
    "discovery":            "Discovery",
    "lateral_movement":     "Lateral Movement",
    "collection":           "Collection",
    "command_and_control":  "Command and Control",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
}

# ── Technique name lookup (most common in Sigma rules) ────────────────────────
# Format: "T{id}" or "T{id}.{sub}" → (name, tactic_key)

TECHNIQUE_NAMES: dict[str, tuple[str, str]] = {
    # Execution
    "T1059":     ("Command and Scripting Interpreter", "execution"),
    "T1059.001": ("PowerShell", "execution"),
    "T1059.002": ("AppleScript", "execution"),
    "T1059.003": ("Windows Command Shell", "execution"),
    "T1059.004": ("Unix Shell", "execution"),
    "T1059.005": ("Visual Basic", "execution"),
    "T1059.006": ("Python", "execution"),
    "T1059.007": ("JavaScript", "execution"),
    "T1204":     ("User Execution", "execution"),
    "T1204.001": ("Malicious Link", "execution"),
    "T1204.002": ("Malicious File", "execution"),
    "T1106":     ("Native API", "execution"),
    "T1053":     ("Scheduled Task/Job", "execution"),
    "T1053.005": ("Scheduled Task", "execution"),
    "T1569":     ("System Services", "execution"),
    "T1569.002": ("Service Execution", "execution"),
    "T1047":     ("Windows Management Instrumentation", "execution"),
    "T1546":     ("Event Triggered Execution", "persistence"),
    # Persistence
    "T1547":     ("Boot or Logon Autostart Execution", "persistence"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1543":     ("Create or Modify System Process", "persistence"),
    "T1543.003": ("Windows Service", "persistence"),
    "T1136":     ("Create Account", "persistence"),
    "T1136.001": ("Local Account", "persistence"),
    "T1136.002": ("Domain Account", "persistence"),
    "T1098":     ("Account Manipulation", "persistence"),
    "T1505":     ("Server Software Component", "persistence"),
    "T1505.003": ("Web Shell", "persistence"),
    # Privilege Escalation
    "T1548":     ("Abuse Elevation Control Mechanism", "privilege_escalation"),
    "T1548.002": ("Bypass User Account Control", "privilege_escalation"),
    "T1134":     ("Access Token Manipulation", "privilege_escalation"),
    "T1134.001": ("Token Impersonation/Theft", "privilege_escalation"),
    "T1055":     ("Process Injection", "privilege_escalation"),
    "T1055.001": ("Dynamic-link Library Injection", "privilege_escalation"),
    "T1055.012": ("Process Hollowing", "privilege_escalation"),
    # Defense Evasion
    "T1027":     ("Obfuscated Files or Information", "defense_evasion"),
    "T1027.001": ("Binary Padding", "defense_evasion"),
    "T1036":     ("Masquerading", "defense_evasion"),
    "T1036.003": ("Rename System Utilities", "defense_evasion"),
    "T1036.005": ("Match Legitimate Name or Location", "defense_evasion"),
    "T1070":     ("Indicator Removal", "defense_evasion"),
    "T1070.001": ("Clear Windows Event Logs", "defense_evasion"),
    "T1070.004": ("File Deletion", "defense_evasion"),
    "T1112":     ("Modify Registry", "defense_evasion"),
    "T1218":     ("System Binary Proxy Execution", "defense_evasion"),
    "T1218.001": ("Compiled HTML File", "defense_evasion"),
    "T1218.005": ("Mshta", "defense_evasion"),
    "T1218.007": ("Msiexec", "defense_evasion"),
    "T1218.010": ("Regsvr32", "defense_evasion"),
    "T1218.011": ("Rundll32", "defense_evasion"),
    "T1562":     ("Impair Defenses", "defense_evasion"),
    "T1562.001": ("Disable or Modify Tools", "defense_evasion"),
    "T1562.002": ("Disable Windows Event Logging", "defense_evasion"),
    "T1574":     ("Hijack Execution Flow", "defense_evasion"),
    "T1574.002": ("DLL Side-Loading", "defense_evasion"),
    # Credential Access
    "T1003":     ("OS Credential Dumping", "credential_access"),
    "T1003.001": ("LSASS Memory", "credential_access"),
    "T1003.002": ("Security Account Manager", "credential_access"),
    "T1003.003": ("NTDS", "credential_access"),
    "T1552":     ("Unsecured Credentials", "credential_access"),
    "T1552.001": ("Credentials In Files", "credential_access"),
    "T1557":     ("Adversary-in-the-Middle", "credential_access"),
    "T1110":     ("Brute Force", "credential_access"),
    "T1558":     ("Steal or Forge Kerberos Tickets", "credential_access"),
    "T1558.003": ("Kerberoasting", "credential_access"),
    # Discovery
    "T1082":     ("System Information Discovery", "discovery"),
    "T1083":     ("File and Directory Discovery", "discovery"),
    "T1057":     ("Process Discovery", "discovery"),
    "T1049":     ("System Network Connections Discovery", "discovery"),
    "T1016":     ("System Network Configuration Discovery", "discovery"),
    "T1033":     ("System Owner/User Discovery", "discovery"),
    "T1087":     ("Account Discovery", "discovery"),
    "T1069":     ("Permission Groups Discovery", "discovery"),
    "T1135":     ("Network Share Discovery", "discovery"),
    "T1046":     ("Network Service Discovery", "discovery"),
    "T1518":     ("Software Discovery", "discovery"),
    # Lateral Movement
    "T1021":     ("Remote Services", "lateral_movement"),
    "T1021.001": ("Remote Desktop Protocol", "lateral_movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "lateral_movement"),
    "T1021.006": ("Windows Remote Management", "lateral_movement"),
    "T1570":     ("Lateral Tool Transfer", "lateral_movement"),
    "T1550":     ("Use Alternate Authentication Material", "lateral_movement"),
    "T1550.002": ("Pass the Hash", "lateral_movement"),
    # Collection
    "T1005":     ("Data from Local System", "collection"),
    "T1039":     ("Data from Network Shared Drive", "collection"),
    "T1056":     ("Input Capture", "collection"),
    "T1074":     ("Data Staged", "collection"),
    "T1113":     ("Screen Capture", "collection"),
    # Command and Control
    "T1071":     ("Application Layer Protocol", "command_and_control"),
    "T1071.001": ("Web Protocols", "command_and_control"),
    "T1071.004": ("DNS", "command_and_control"),
    "T1095":     ("Non-Application Layer Protocol", "command_and_control"),
    "T1105":     ("Ingress Tool Transfer", "command_and_control"),
    "T1219":     ("Remote Access Software", "command_and_control"),
    # Exfiltration
    "T1041":     ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1048":     ("Exfiltration Over Alternative Protocol", "exfiltration"),
    "T1567":     ("Exfiltration Over Web Service", "exfiltration"),
    # Impact
    "T1486":     ("Data Encrypted for Impact", "impact"),
    "T1490":     ("Inhibit System Recovery", "impact"),
    "T1489":     ("Service Stop", "impact"),
    "T1529":     ("System Shutdown/Reboot", "impact"),
    # Initial Access
    "T1566":     ("Phishing", "initial_access"),
    "T1566.001": ("Spearphishing Attachment", "initial_access"),
    "T1566.002": ("Spearphishing Link", "initial_access"),
    "T1190":     ("Exploit Public-Facing Application", "initial_access"),
    "T1133":     ("External Remote Services", "initial_access"),
    "T1078":     ("Valid Accounts", "initial_access"),
    "T1195":     ("Supply Chain Compromise", "initial_access"),
}

_TAG_TECHNIQUE = re.compile(r'^attack\.(t\d{4}(?:\.\d{3})?)$', re.IGNORECASE)
_TAG_TACTIC = re.compile(r'^attack\.([a-z_]+)$', re.IGNORECASE)


def compute_coverage(rule_yamls: list[str]) -> dict[str, Any]:
    """
    Parse a list of Sigma rule YAMLs and return an ATT&CK coverage report.

    Returns:
        {
          total_rules, parsed_rules, covered_techniques (count),
          covered_tactics (list of tactic keys),
          techniques: [ {id, name, tactic, tactic_display, rules} ],
          by_tactic: { tactic_key: [technique_ids] },
          uncovered_tactics: [tactic_keys],
          rule_index: { rule_title: [technique_ids] },
        }
    """
    technique_to_rules: dict[str, list[str]] = {}
    covered_tactics: set[str] = set()
    rule_index: dict[str, list[str]] = {}
    parsed = 0

    for raw in rule_yamls:
        try:
            data = yaml.safe_load(raw)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        parsed += 1

        title = str(data.get("title", f"rule_{parsed}"))
        tags: list[str] = data.get("tags", []) or []
        rule_techniques: list[str] = []

        for tag in tags:
            tag = str(tag).lower()

            m = _TAG_TECHNIQUE.match(tag)
            if m:
                tid = m.group(1).upper()
                technique_to_rules.setdefault(tid, [])
                if title not in technique_to_rules[tid]:
                    technique_to_rules[tid].append(title)
                if tid not in rule_techniques:
                    rule_techniques.append(tid)

                # Infer tactic from lookup
                info = TECHNIQUE_NAMES.get(tid)
                if info:
                    covered_tactics.add(info[1])
                continue

            m = _TAG_TACTIC.match(tag)
            if m:
                tactic_key = m.group(1).lower()
                if tactic_key in TACTICS:
                    covered_tactics.add(tactic_key)

        rule_index[title] = rule_techniques

    # Build technique list
    techniques = []
    by_tactic: dict[str, list[str]] = {}

    for tid, rules in sorted(technique_to_rules.items()):
        info = TECHNIQUE_NAMES.get(tid)
        name = info[0] if info else tid
        tactic_key = info[1] if info else "unknown"
        tactic_display = TACTICS.get(tactic_key, tactic_key.replace("_", " ").title())

        techniques.append({
            "id": tid,
            "name": name,
            "tactic": tactic_key,
            "tactic_display": tactic_display,
            "rules": rules,
        })
        by_tactic.setdefault(tactic_key, [])
        if tid not in by_tactic[tactic_key]:
            by_tactic[tactic_key].append(tid)

    uncovered = [t for t in TACTICS if t not in covered_tactics]

    return {
        "total_rules": len(rule_yamls),
        "parsed_rules": parsed,
        "covered_techniques": len(technique_to_rules),
        "covered_tactics": sorted(covered_tactics),
        "techniques": techniques,
        "by_tactic": by_tactic,
        "uncovered_tactics": uncovered,
        "rule_index": rule_index,
    }


def build_navigator_layer(coverage_data: dict[str, Any]) -> dict[str, Any]:
    """
    Serialise a coverage report into a valid ATT&CK Navigator 4.x layer JSON.
    Colour scale: white (0 rules) → light green (1) → green (2-3) → dark green (7+).
    """
    techniques_in_layer = []

    for tech in coverage_data.get("techniques", []):
        rule_count = len(tech.get("rules", []))
        if rule_count == 0:
            continue
        if rule_count == 1:
            color = "#C3E6CB"
        elif rule_count <= 3:
            color = "#54B399"
        elif rule_count <= 6:
            color = "#017D73"
        else:
            color = "#004643"

        techniques_in_layer.append({
            "techniqueID": tech["id"],
            "tactic": tech["tactic"].replace("_", "-"),
            "color": color,
            "comment": f"{rule_count} rule{'s' if rule_count > 1 else ''}: " + ", ".join(tech.get("rules", [])[:5]),
            "enabled": True,
            "score": rule_count,
            "metadata": [],
        })

    return {
        "name": "Sigma AI — Detection Coverage",
        "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Auto-generated by Sigma AI. {coverage_data.get('covered_techniques', 0)} techniques covered across {coverage_data.get('total_rules', 0)} rules.",
        "filters": {"platforms": ["Windows", "Linux", "macOS", "Network", "Cloud"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True},
        "hideDisabled": False,
        "techniques": techniques_in_layer,
        "gradient": {
            "colors": ["#ffffff", "#C3E6CB", "#54B399", "#017D73", "#004643"],
            "minValue": 0,
            "maxValue": 7,
        },
        "legendItems": [
            {"label": "1 rule", "color": "#C3E6CB"},
            {"label": "2–3 rules", "color": "#54B399"},
            {"label": "4–6 rules", "color": "#017D73"},
            {"label": "7+ rules", "color": "#004643"},
        ],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
