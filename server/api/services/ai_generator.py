"""
AI rule generation service.

Supports multiple LLM providers:
  - anthropic      : Anthropic Claude (default)
  - openai         : OpenAI GPT models
  - openai_compat  : Any OpenAI-compatible endpoint (Ollama, LM Studio, llama.cpp, etc.)

Provider is selected at call time via the `provider` parameter. API keys and
base URLs are forwarded from the Kibana plugin as request headers so they never
need to be baked into the container image.
"""

import ipaddress
import json
import logging
import os
import socket
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"
DEFAULT_OPENAI_MODEL = "gpt-4o"
MAX_TOKENS = 4096

PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_OPENAI = "openai"
PROVIDER_OPENAI_COMPAT = "openai_compat"
PROVIDER_OLLAMA = "ollama"  # alias for openai_compat


def _assert_base_url_allowed(url: str) -> None:
    """Guard against SSRF via an attacker-supplied LLM base_url.

    Blocks link-local addresses — which include the 169.254.169.254 cloud-metadata
    endpoint (AWS/GCP/Azure) — and known metadata hostnames. Localhost, private-LAN
    and public hosts are allowed so local models (Ollama, LM Studio) keep working.
    """
    host = (urlparse(url).hostname or "").lower()
    if not host:
        raise ValueError("Invalid LLM base_url")
    if host in {"metadata.google.internal", "metadata.goog"}:
        raise ValueError(f"LLM base_url host '{host}' is not allowed")
    try:
        resolved = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except socket.gaierror:
        return  # unresolvable — let the HTTP client surface the error normally
    for ip in resolved:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_link_local:
            raise ValueError("LLM base_url resolves to a link-local address (blocked for SSRF protection)")


def _truncate_fields(fields: dict, max_fields: int = 80) -> dict:
    items = sorted(fields.items())
    return dict(items[:max_fields])


def _truncate_events(events: list, max_events: int = 3) -> list:
    return events[:max_events]


def _call_llm(
    system: str,
    user: str,
    provider: str = PROVIDER_ANTHROPIC,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
) -> str:
    """Unified LLM call. Routes to the correct SDK based on provider."""
    provider = (provider or PROVIDER_ANTHROPIC).lower()

    if provider == PROVIDER_ANTHROPIC:
        key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        if not key:
            raise RuntimeError(
                "Anthropic API key not configured. Set it in Settings → Integration & Status."
            )
        import anthropic
        client = anthropic.Anthropic(api_key=key)
        effective_model = model or DEFAULT_ANTHROPIC_MODEL
        msg = client.messages.create(
            model=effective_model,
            max_tokens=MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return msg.content[0].text

    elif provider in (PROVIDER_OPENAI, PROVIDER_OPENAI_COMPAT, PROVIDER_OLLAMA):
        from openai import OpenAI
        effective_base = base_url or (
            "http://host.docker.internal:11434/v1" if provider == PROVIDER_OLLAMA
            else "https://api.openai.com/v1"
        )
        _assert_base_url_allowed(effective_base)
        effective_key = api_key or os.getenv("OPENAI_API_KEY", "ollama")
        effective_model = model or (
            "llama3.2" if provider == PROVIDER_OLLAMA else DEFAULT_OPENAI_MODEL
        )
        client = OpenAI(api_key=effective_key, base_url=effective_base)
        resp = client.chat.completions.create(
            model=effective_model,
            max_tokens=MAX_TOKENS,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content or ""

    else:
        raise RuntimeError(
            f"Unknown LLM provider '{provider}'. Choose: anthropic, openai, openai_compat, ollama."
        )


# Keep legacy alias so existing callers inside this module don't break during transition
def _call_claude(system: str, user: str, api_key: Optional[str] = None) -> str:
    return _call_llm(system, user, provider=PROVIDER_ANTHROPIC, api_key=api_key)


def _call_llm_chat(
    system: str,
    messages: list[dict],
    provider: str = PROVIDER_ANTHROPIC,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    model: Optional[str] = None,
) -> str:
    """Multi-turn LLM call that accepts a full conversation history."""
    provider = (provider or PROVIDER_ANTHROPIC).lower()

    if provider == PROVIDER_ANTHROPIC:
        key = api_key or os.getenv("ANTHROPIC_API_KEY", "")
        if not key:
            raise RuntimeError(
                "Anthropic API key not configured. Set it in Settings → Integration & Status."
            )
        import anthropic
        client = anthropic.Anthropic(api_key=key)
        msg = client.messages.create(
            model=model or DEFAULT_ANTHROPIC_MODEL,
            max_tokens=MAX_TOKENS,
            system=system,
            messages=messages,
        )
        return msg.content[0].text

    elif provider in (PROVIDER_OPENAI, PROVIDER_OPENAI_COMPAT, PROVIDER_OLLAMA):
        from openai import OpenAI
        effective_base = base_url or (
            "http://host.docker.internal:11434/v1" if provider == PROVIDER_OLLAMA
            else "https://api.openai.com/v1"
        )
        _assert_base_url_allowed(effective_base)
        effective_key = api_key or os.getenv("OPENAI_API_KEY", "ollama")
        effective_model = model or (
            "llama3.2" if provider == PROVIDER_OLLAMA else DEFAULT_OPENAI_MODEL
        )
        client = OpenAI(api_key=effective_key, base_url=effective_base)
        resp = client.chat.completions.create(
            model=effective_model,
            max_tokens=MAX_TOKENS,
            messages=[{"role": "system", "content": system}] + messages,
        )
        return resp.choices[0].message.content or ""

    else:
        raise RuntimeError(
            f"Unknown LLM provider '{provider}'. Choose: anthropic, openai, openai_compat, ollama."
        )


_CHANGES_SPLIT_RE = __import__('re').compile(
    r'\n---+\s*(?:CHANGES---|\nCHANGES\b)',
    __import__('re').IGNORECASE,
)


def _split_improve_output(text: str):
    """Split improve output into (yaml_part, changes_part). Handles both
    the instructed '---CHANGES---' literal and the common model variant
    where '---' and 'CHANGES:' appear on separate lines."""
    import re
    # Exact literal first (cheapest)
    if "---CHANGES---" in text:
        parts = text.split("---CHANGES---", 1)
        return parts[0], parts[1].lstrip('\n').strip()
    # Model wrote '---\nCHANGES:' or '---\nCHANGES\n'
    m = re.search(r'\n(---+)\s*\n+CHANGES[:\s]', text, re.IGNORECASE)
    if m:
        yaml_part = text[:m.start()]
        changes_part = text[m.end():].strip()
        return yaml_part, changes_part
    return text, ""


def _extract_sigma_yaml(text: str) -> str:
    """
    Extract the SIGMA YAML from LLM output that may contain prose and/or code fences.
    Priority:
      1. Content inside the first ```yaml / ```yml / ``` block
      2. Everything from the first recognisable SIGMA key onward
      3. Original text unchanged (fallback)
    """
    import re
    # Strip code fences — grab content between first opening and closing fence
    fence = re.search(r'```(?:yaml|yml)?\s*\n(.*?)(?:```|$)', text, re.DOTALL | re.IGNORECASE)
    if fence:
        return fence.group(1).strip()

    # No fences — find where the YAML actually begins
    sigma_keys = ('title:', 'id:', 'status:', 'logsource:', 'detection:')
    for i, line in enumerate(text.split('\n')):
        if any(line.strip().startswith(k) for k in sigma_keys):
            return '\n'.join(text.split('\n')[i:]).strip()

    return text.strip()


# ── System prompts ─────────────────────────────────────────────────────────────

_SIGMA_EXPERT_BASE = """You are a senior detection engineer with deep expertise in SIGMA rules,
the Elastic Common Schema (ECS), MITRE ATT&CK, and the pySigma ecosystem.

OUTPUT FORMAT — follow this exactly:
- Output raw YAML only. No introductory text. No markdown fences (```). No explanation after.
- Start your response with the first YAML key (e.g. "title:").

DETECTION SYNTAX — the detection block must use ECS field names with optional modifiers:
  fieldname: value
  fieldname|contains: substring
  fieldname|endswith: suffix
  fieldname|startswith: prefix
  fieldname: [value1, value2]

Do NOT invent fields like "field_name", "type", "value", "and_or_value", "match_value".
Use only real ECS fields (e.g. process.name, CommandLine, Image, DestinationIp, SourceIp).

REQUIRED STRUCTURE (copy this pattern exactly):
title: Descriptive Rule Title
status: experimental
description: One sentence describing what is detected.
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp: '192.168.1.100'
    condition: selection
level: medium
tags:
    - attack.t1071
    - attack.command_and_control
falsepositives:
    - Legitimate business traffic

STRICT RULES:
- Omit the `id:` field entirely (safest). If included, it MUST be a UUID4 like a1b2c3d4-e5f6-4789-a012-b3c4d5e6f7a8.
- detection selections must have real non-empty ECS field values — no placeholders, no blank strings.
- condition must reference selection names defined above it."""


_DRAFT_FROM_IOCS_SYSTEM = _SIGMA_EXPERT_BASE + """

You will receive IOCs and live field context from an Elasticsearch environment.
Use the available fields to write a rule that maps accurately to the ECS fields
present in that environment. Prefer specific field matches over wildcard queries."""


_EXPLAIN_SYSTEM = """You are a detection engineering educator. Given a SIGMA rule YAML,
produce a clear plain-English explanation structured as:

**What it detects:** one paragraph
**Log sources monitored:** bullet list
**Detection logic:** step-by-step walkthrough of the condition
**MITRE ATT&CK:** technique IDs and tactic names referenced
**Potential false positives:** bullet list
**Tuning suggestions:** 1-3 specific suggestions to reduce noise

Be concise and practical. The audience is an analyst who may not be a SIGMA author."""


_IMPROVE_SYSTEM = _SIGMA_EXPERT_BASE + """

You will receive a SIGMA rule and live field context. Return:
1. An improved SIGMA YAML rule (with your changes applied)
2. A brief CHANGES section (bullet list) explaining what you changed and why

Separate them with the literal line: ---CHANGES---"""


_ALERT_TO_SIGMA_SYSTEM = _SIGMA_EXPERT_BASE + """

You will receive a Kibana security alert document (JSON) and field mappings.
Generate a SIGMA rule that would detect the same activity pattern.
Extract: relevant process names, file paths, registry keys, network indicators,
command lines, or other behavioural indicators from the alert.
Map them to the correct ECS fields present in the environment."""


_SO_TO_SIGMA_SYSTEM = _SIGMA_EXPERT_BASE + """

You will receive a Security Onion alert document (JSON) and its source type
(suricata, zeek, or sigma). Generate a host-level SIGMA rule that detects
the same underlying behaviour at the endpoint/log level — not just the network
signature. For Suricata alerts: translate the network indicator to a process or
network connection SIGMA rule. For Zeek alerts: use zeek_* logsource categories."""


_CHAT_SYSTEM = """You are a senior detection engineer and SOC analyst with deep expertise in
SIGMA rules, the Elastic Common Schema (ECS), MITRE ATT&CK, and threat intelligence.

You help with:
- Drafting SIGMA detection rules from natural language descriptions, IOC lists, or CVE/advisory URLs
- Analyzing threat reports and vulnerability advisories to extract detection opportunities
- Explaining attacker techniques and mapping them to SIGMA logsources and ECS fields
- Answering questions about SIGMA syntax, ECS field names, and detection logic

WHEN GENERATING SIGMA RULES — output them in a ```yaml block and follow these rules exactly:

DETECTION SYNTAX — use ONLY these forms inside the detection block:
  fieldname: value                   # exact match
  fieldname|contains: substring      # substring match
  fieldname|startswith: prefix
  fieldname|endswith: suffix
  fieldname|re: regex
  fieldname|gte: 1024                # numeric comparison
  fieldname: [value1, value2]        # OR list

NEVER use ==, !=, >=, <=, >, < operators — those are EQL/KQL, not SIGMA.
NEVER use list items (- value) directly under a selection — use field: value pairs.
NEVER invent field names. Use real ECS fields: process.name, CommandLine, DestinationIp, etc.

REQUIRED STRUCTURE:
title: Descriptive Rule Title
status: experimental
description: One sentence.
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationIp: '10.0.0.1'
        Protocol: tcp
    condition: selection
level: medium
tags:
    - attack.t1071
falsepositives:
    - Legitimate traffic

Omit the id: field entirely. Every field value must be non-empty.

When the user provides a URL, treat the fetched page content as primary context.
Be concise and practical. One clear answer is better than a lengthy hedge."""


# ── Generator methods ──────────────────────────────────────────────────────────

class AIGeneratorService:

    async def draft_from_iocs(
        self,
        iocs: list[str],
        context: dict,
        logsource_hint: Optional[str] = None,
        api_key: Optional[str] = None,
        provider: str = PROVIDER_ANTHROPIC,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ) -> dict:
        fields_summary = json.dumps(_truncate_fields(context.get("field_mappings", {})), indent=2)
        events_summary = json.dumps(_truncate_events(context.get("sample_events", [])), indent=2)
        hint = f"\nPreferred logsource category: {logsource_hint}" if logsource_hint else ""

        user = f"""Generate a SIGMA detection rule for the following IOCs:{hint}

IOCs:
{chr(10).join(f'- {ioc}' for ioc in iocs)}

Available ECS fields in this environment (field → type):
{fields_summary}

Sample matching events:
{events_summary}"""

        try:
            raw = _call_llm(_DRAFT_FROM_IOCS_SYSTEM, user, provider=provider, api_key=api_key, base_url=base_url, model=model)
            yaml_text = _extract_sigma_yaml(raw)
            return {"success": True, "rule_yaml": yaml_text}
        except Exception as e:
            logger.error(f"draft_from_iocs failed: {e}")
            return {"success": False, "message": str(e)}

    async def explain_rule(
        self,
        rule_yaml: str,
        api_key: Optional[str] = None,
        provider: str = PROVIDER_ANTHROPIC,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ) -> dict:
        user = f"Explain this SIGMA rule:\n\n{rule_yaml}"
        try:
            explanation = _call_llm(_EXPLAIN_SYSTEM, user, provider=provider, api_key=api_key, base_url=base_url, model=model)
            return {"success": True, "explanation": explanation.strip()}
        except Exception as e:
            logger.error(f"explain_rule failed: {e}")
            return {"success": False, "message": str(e)}

    async def improve_rule(
        self,
        rule_yaml: str,
        context: dict,
        api_key: Optional[str] = None,
        provider: str = PROVIDER_ANTHROPIC,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ) -> dict:
        fields_summary = json.dumps(_truncate_fields(context.get("field_mappings", {})), indent=2)
        user = f"""Review and improve this SIGMA rule.

Current rule:
{rule_yaml}

Available ECS fields in this environment:
{fields_summary}"""

        try:
            raw = _call_llm(_IMPROVE_SYSTEM, user, provider=provider, api_key=api_key, base_url=base_url, model=model)
            yaml_part, changes = _split_improve_output(raw)
            improved_yaml = _extract_sigma_yaml(yaml_part)
            return {"success": True, "rule_yaml": improved_yaml, "changes": changes}
        except Exception as e:
            logger.error(f"improve_rule failed: {e}")
            return {"success": False, "message": str(e)}

    async def draft_from_alert(
        self,
        context: dict,
        api_key: Optional[str] = None,
        provider: str = PROVIDER_ANTHROPIC,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ) -> dict:
        if "error" in context:
            return {"success": False, "message": context["error"]}

        alert_summary = json.dumps(context.get("alert_doc", {}), indent=2)
        fields_summary = json.dumps(_truncate_fields(context.get("field_mappings", {})), indent=2)
        user = f"""Convert this Kibana security alert to a SIGMA rule:

Alert document:
{alert_summary}

Available ECS fields in this environment:
{fields_summary}"""

        try:
            raw = _call_llm(_ALERT_TO_SIGMA_SYSTEM, user, provider=provider, api_key=api_key, base_url=base_url, model=model)
            yaml_text = _extract_sigma_yaml(raw)
            return {"success": True, "rule_yaml": yaml_text, "source_type": "kibana_security"}
        except Exception as e:
            logger.error(f"draft_from_alert failed: {e}")
            return {"success": False, "message": str(e)}

    async def chat(
        self,
        messages: list[dict],
        rule_context: Optional[str] = None,
        provider: str = PROVIDER_ANTHROPIC,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ) -> dict:
        system = _CHAT_SYSTEM
        if rule_context and rule_context.strip():
            system += (
                f"\n\nThe user currently has this SIGMA rule open in their editor "
                f"— use it as context when relevant:\n```yaml\n{rule_context.strip()}\n```"
            )
        try:
            reply = _call_llm_chat(
                system, messages,
                provider=provider, api_key=api_key, base_url=base_url, model=model,
            )
            return {"success": True, "reply": reply.strip()}
        except Exception as e:
            logger.error(f"chat failed: {e}")
            return {"success": False, "message": str(e)}

    async def draft_from_so_alert(
        self,
        context: dict,
        api_key: Optional[str] = None,
        provider: str = PROVIDER_ANTHROPIC,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ) -> dict:
        if "error" in context:
            return {"success": False, "message": context["error"]}

        alert_summary = json.dumps(context.get("alert_doc", {}), indent=2)
        fields_summary = json.dumps(_truncate_fields(context.get("field_mappings", {})), indent=2)
        source_type = context.get("source_type", "unknown")

        user = f"""Convert this Security Onion alert (source: {source_type}) to a SIGMA rule:

Alert document:
{alert_summary}

Available fields in this environment:
{fields_summary}"""

        try:
            raw = _call_llm(_SO_TO_SIGMA_SYSTEM, user, provider=provider, api_key=api_key, base_url=base_url, model=model)
            yaml_text = _extract_sigma_yaml(raw)
            return {"success": True, "rule_yaml": yaml_text, "source_type": source_type}
        except Exception as e:
            logger.error(f"draft_from_so_alert failed: {e}")
            return {"success": False, "message": str(e)}
