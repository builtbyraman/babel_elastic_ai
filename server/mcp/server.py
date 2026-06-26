#!/usr/bin/env python3
"""
sigma-ai MCP Server

Exposes sigma-ai capabilities as MCP tools usable by Claude Code,
Claude Desktop, or any MCP-compatible client.

Usage:
    python server.py

Claude Code config (~/.claude.json or via /mcp add):
    {
      "mcpServers": {
        "sigma-ai": {
          "command": "python",
          "args": ["/path/to/sigma_ai/server/mcp/server.py"],
          "env": {
            "SIGMA_API_URL": "http://localhost:5000",
            "SIGMA_MCP_ALLOW_DEPLOY": "false"
          }
        }
      }
    }

Environment variables:
    SIGMA_API_URL            sigma-api base URL (default: http://localhost:5000)
    SIGMA_API_KEY            Bearer token for sigma-api (optional)
    SIGMA_MCP_ALLOW_DEPLOY   Set to "true" to enable deploy_rule (default: disabled)
    SIGMA_MCP_AUDIT_LOG      Path for audit log (default: ./audit.log)
"""

import json
import logging
import os
import re
import sys
from typing import Any

import httpx
import yaml
from mcp.server.fastmcp import FastMCP

from guardrails import (
    GuardrailError,
    audit,
    check_deploy_allowed,
    check_rate_limit,
    sanitize_es_result,
    validate_esql,
    validate_index_pattern,
    validate_limit,
    validate_sigma_input,
    validate_timeframe,
    MAX_ES_HITS,
    MAX_FIELD_COUNT,
)

logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────

# sigma-api (FastAPI) — handles convert/validate/test/coverage and the /v1/ai/* tools.
SIGMA_API_URL = os.getenv("SIGMA_API_URL", "http://localhost:8001").rstrip("/")
SIGMA_API_KEY = os.getenv("SIGMA_API_KEY", "")

# Kibana — search_rules and deploy_rule are served by the Babel Kibana plugin,
# not the sigma-api, so they need a separate base URL + login.
KIBANA_URL = os.getenv("KIBANA_URL", "http://localhost:5601").rstrip("/")
KIBANA_USERNAME = os.getenv("KIBANA_USERNAME", "elastic")
KIBANA_PASSWORD = os.getenv("KIBANA_PASSWORD", "changeme")

# LLM provider for the AI tools. The sigma-api defaults to Anthropic (and needs a
# key); these headers steer it to a local model instead. base_url is dialled from
# inside the sigma-api container, so it must be reachable from there (on the Docker
# stack that is host.docker.internal, not localhost).
LLM_PROVIDER = os.getenv("SIGMA_MCP_LLM_PROVIDER", "ollama")
LLM_MODEL = os.getenv(
    "SIGMA_MCP_LLM_MODEL",
    "hf.co/yuxinlu1/gemma-4-12B-coder-fable5-composer2.5-v1-GGUF:Q4_K_M",
)
LLM_BASE_URL = os.getenv("SIGMA_MCP_LLM_BASE_URL", "http://host.docker.internal:11434/v1")
LLM_API_KEY = os.getenv("SIGMA_MCP_LLM_API_KEY", "")

# Local models are slow (a 12B reasoning model is ~30-90s per call).
AI_TIMEOUT = float(os.getenv("SIGMA_MCP_AI_TIMEOUT", "240"))


def _api_headers() -> dict[str, str]:
    h = {"Content-Type": "application/json"}
    if SIGMA_API_KEY:
        h["Authorization"] = f"Bearer {SIGMA_API_KEY}"
    return h


def _llm_headers() -> dict[str, str]:
    """sigma-api headers + the x-llm-* provider selection used by /v1/ai/* routes."""
    h = _api_headers()
    if LLM_PROVIDER:
        h["x-llm-provider"] = LLM_PROVIDER
    if LLM_MODEL:
        h["x-llm-model"] = LLM_MODEL
    if LLM_BASE_URL:
        h["x-llm-base-url"] = LLM_BASE_URL
    if LLM_API_KEY:
        h["x-anthropic-api-key" if LLM_PROVIDER == "anthropic" else "x-llm-api-key"] = LLM_API_KEY
    return h


async def _post(path: str, body: dict, *, llm: bool = False) -> Any:
    """POST to sigma-api. Set llm=True for /v1/ai/* tools that invoke the model."""
    headers = _llm_headers() if llm else _api_headers()
    timeout = AI_TIMEOUT if llm else 60
    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(f"{SIGMA_API_URL}{path}", json=body, headers=headers)
        r.raise_for_status()
        return r.json()


async def _get(path: str, params: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(f"{SIGMA_API_URL}{path}", params=params, headers=_api_headers())
        r.raise_for_status()
        return r.json()


# ── Kibana plugin calls (search_rules, deploy_rule) ─────────────────────────────

def _kbn_auth() -> tuple[str, str] | None:
    return (KIBANA_USERNAME, KIBANA_PASSWORD) if KIBANA_USERNAME else None


async def _kbn_get(path: str, params: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(f"{KIBANA_URL}{path}", params=params, auth=_kbn_auth())
        r.raise_for_status()
        return r.json()


async def _kbn_post(path: str, body: dict) -> Any:
    headers = {"Content-Type": "application/json", "kbn-xsrf": "sigma-mcp"}
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(f"{KIBANA_URL}{path}", json=body, headers=headers, auth=_kbn_auth())
        r.raise_for_status()
        return r.json()


# ── MCP server ─────────────────────────────────────────────────────────────────

mcp = FastMCP(
    "sigma-ai",
    instructions=(
        "SIGMA detection engineering tools: convert, validate, test, draft, explain, "
        "and deploy SIGMA rules. Query Elasticsearch field mappings and live log data."
    ),
)


# ── Tool: convert_rule ─────────────────────────────────────────────────────────

@mcp.tool()
async def convert_rule(
    rule_yaml: str,
    format: str = "eql",
    pipeline: str = "ecs_windows",
) -> str:
    """
    Convert a SIGMA rule YAML to a query format suitable for Elasticsearch.

    Args:
        rule_yaml: Complete SIGMA rule as YAML text.
        format: Target format — eql (default), esql, lucene, kibana_ndjson, siem_rule.
        pipeline: Field-mapping pipeline — ecs_windows (default), ecs_linux, zeek, macos.

    Returns:
        The converted query string, or an error message.
    """
    tool = "convert_rule"
    params = {"format": format, "pipeline": pipeline}
    try:
        check_rate_limit(tool)
        validate_sigma_input(rule_yaml)
        result = await _post("/v1/conversions", {"rule_yaml": rule_yaml, "format": format, "pipeline": pipeline})
        output = result.get("query_result", json.dumps(result))
        audit(tool, params, "allowed")
        return output
    except GuardrailError as e:
        audit(tool, params, "blocked", str(e))
        return f"[BLOCKED] {e}"
    except Exception as e:
        audit(tool, params, "error", str(e))
        return f"[ERROR] {e}"


# ── Tool: validate_rule ────────────────────────────────────────────────────────

@mcp.tool()
async def validate_rule(rule_yaml: str) -> str:
    """
    Validate a SIGMA rule and return a list of errors and warnings.

    Args:
        rule_yaml: Complete SIGMA rule as YAML text.

    Returns:
        Validation result — 'valid' or a list of issues with severity and message.
    """
    tool = "validate_rule"
    try:
        check_rate_limit(tool)
        validate_sigma_input(rule_yaml)
        result = await _post("/v1/rules/validate", {"rule_yaml": rule_yaml})
        if result.get("valid"):
            output = "✓ Rule is valid — no errors found."
            if result.get("issues"):
                output += "\nWarnings:\n" + "\n".join(
                    f"  [{i['type']}] {i['message']}" for i in result["issues"]
                )
        else:
            issues = result.get("issues", [])
            output = f"✗ Rule has {len(issues)} issue(s):\n" + "\n".join(
                f"  [{i['type'].upper()}] {i['message']}" for i in issues
            )
        audit(tool, {}, "allowed")
        return output
    except GuardrailError as e:
        audit(tool, {}, "blocked", str(e))
        return f"[BLOCKED] {e}"
    except Exception as e:
        audit(tool, {}, "error", str(e))
        return f"[ERROR] {e}"


# ── Tool: test_rule ────────────────────────────────────────────────────────────

@mcp.tool()
async def test_rule(
    rule_yaml: str,
    index_pattern: str = "*",
    timeframe_hours: int = 24,
    pipeline: str = "ecs_windows",
) -> str:
    """
    Test a SIGMA rule against live Elasticsearch data and return hit count and sample events.

    Args:
        rule_yaml: Complete SIGMA rule as YAML text.
        index_pattern: Elasticsearch index pattern to query (default: *).
        timeframe_hours: How many hours of recent data to search, 1–168 (default: 24).
        pipeline: Field-mapping pipeline (default: ecs_windows).

    Returns:
        Hit count, query timing, and up to 5 sample matching events.
    """
    tool = "test_rule"
    params = {"index_pattern": index_pattern, "timeframe_hours": timeframe_hours}
    try:
        check_rate_limit(tool)
        validate_sigma_input(rule_yaml)
        validate_index_pattern(index_pattern)
        validate_timeframe(timeframe_hours)
        result = await _post("/v1/test-runs", {
            "rule_yaml": rule_yaml,
            "index_pattern": index_pattern,
            "timeframe_hours": timeframe_hours,
            "pipeline": pipeline,
            "query_format": "eql",
        })
        data = result.get("data", result)
        hits = data.get("hit_count", 0)
        timing = data.get("timing_ms", "?")
        samples = data.get("sample_events", [])[:5]
        lines = [f"Hit count: {hits} ({timing}ms)"]
        if samples:
            lines.append(f"\nSample events ({len(samples)}):")
            for s in samples:
                lines.append("  " + sanitize_es_result(s.get("source", s))[:500])
        audit(tool, params, "allowed", f"hits={hits}")
        return "\n".join(lines)
    except GuardrailError as e:
        audit(tool, params, "blocked", str(e))
        return f"[BLOCKED] {e}"
    except Exception as e:
        audit(tool, params, "error", str(e))
        return f"[ERROR] {e}"


# ── Tool: draft_from_iocs ──────────────────────────────────────────────────────

@mcp.tool()
async def draft_from_iocs(
    iocs: list[str],
    logsource_hint: str = "",
    index_pattern: str = "logs-*",
) -> str:
    """
    Draft a SIGMA detection rule from a list of IOCs (IPs, hashes, domains, process names, etc.).

    Args:
        iocs: List of IOC strings, one per item.
        logsource_hint: Optional preferred SIGMA logsource category
                        (process_creation, network_connection, file_event, etc.).
        index_pattern: Elasticsearch index pattern used to gather field context.

    Returns:
        Generated SIGMA rule as YAML, ready to be loaded into the editor or converted.
    """
    tool = "draft_from_iocs"
    params = {"ioc_count": len(iocs), "logsource_hint": logsource_hint}
    try:
        check_rate_limit(tool)
        if not iocs:
            raise GuardrailError("iocs list is empty — provide at least one IOC.")
        if len(iocs) > 50:
            raise GuardrailError("Too many IOCs (max 50). Batch large lists.")
        validate_index_pattern(index_pattern)
        result = await _post("/v1/ai/draft-from-iocs", {
            "iocs": iocs,
            "index_pattern": index_pattern,
            "logsource_hint": logsource_hint or None,
        }, llm=True)
        output = result.get("rule_yaml") or result.get("message", "No output")
        audit(tool, params, "allowed")
        return output
    except GuardrailError as e:
        audit(tool, params, "blocked", str(e))
        return f"[BLOCKED] {e}"
    except Exception as e:
        audit(tool, params, "error", str(e))
        return f"[ERROR] {e}"


# ── Tool: explain_rule ─────────────────────────────────────────────────────────

@mcp.tool()
async def explain_rule(rule_yaml: str) -> str:
    """
    Explain a SIGMA rule in plain English — what it detects, the log sources it monitors,
    the detection logic, MITRE ATT&CK mappings, false positives, and tuning suggestions.

    Args:
        rule_yaml: Complete SIGMA rule as YAML text.

    Returns:
        Structured plain-English explanation of the rule.
    """
    tool = "explain_rule"
    try:
        check_rate_limit(tool)
        validate_sigma_input(rule_yaml)
        result = await _post("/v1/ai/explain", {"rule_yaml": rule_yaml}, llm=True)
        output = result.get("explanation") or result.get("message", "No output")
        audit(tool, {}, "allowed")
        return output
    except GuardrailError as e:
        audit(tool, {}, "blocked", str(e))
        return f"[BLOCKED] {e}"
    except Exception as e:
        audit(tool, {}, "error", str(e))
        return f"[ERROR] {e}"


# ── Tool: improve_rule ─────────────────────────────────────────────────────────

@mcp.tool()
async def improve_rule(
    rule_yaml: str,
    index_pattern: str = "logs-*",
) -> str:
    """
    Analyse a SIGMA rule against live ES field mappings and return an improved version
    with a summary of what changed and why.

    Args:
        rule_yaml: Complete SIGMA rule as YAML text.
        index_pattern: Elasticsearch index pattern used to gather field context.

    Returns:
        Improved SIGMA rule YAML followed by a CHANGES section.
    """
    tool = "improve_rule"
    params = {"index_pattern": index_pattern}
    try:
        check_rate_limit(tool)
        validate_sigma_input(rule_yaml)
        validate_index_pattern(index_pattern)
        result = await _post("/v1/ai/improve", {
            "rule_yaml": rule_yaml,
            "index_pattern": index_pattern,
        }, llm=True)
        improved = result.get("rule_yaml", "")
        changes  = result.get("changes", "")
        output   = improved
        if changes:
            output += f"\n\n---CHANGES---\n{changes}"
        audit(tool, params, "allowed")
        return output or result.get("message", "No output")
    except GuardrailError as e:
        audit(tool, params, "blocked", str(e))
        return f"[BLOCKED] {e}"
    except Exception as e:
        audit(tool, params, "error", str(e))
        return f"[ERROR] {e}"


# ── Tool: query_elasticsearch ──────────────────────────────────────────────────

@mcp.tool()
async def query_elasticsearch(
    esql_query: str,
    limit: int = 20,
) -> str:
    """
    Run a read-only ES|QL query against Elasticsearch and return results.
    Use this to investigate live log data, check field values, or verify detection logic.

    GUARDRAILS: Write operations (DELETE, PUT, UPDATE, etc.) are blocked.
    System indices (.kibana, .security, etc.) are blocked.
    Results are capped at 50 rows and sensitive fields are redacted.

    Args:
        esql_query: A valid ES|QL SELECT query (e.g. "FROM logs-* | WHERE process.name == 'cmd.exe' | LIMIT 10").
        limit: Maximum rows to return, 1–50 (default: 20).

    Returns:
        Query results as JSON, redacted and truncated for safety.
    """
    tool = "query_elasticsearch"
    params = {"limit": limit, "query_preview": esql_query[:80]}
    try:
        check_rate_limit(tool)
        validate_esql(esql_query)
        validate_limit(limit)

        # Enforce LIMIT in query — append or replace
        enforced_limit = min(limit, MAX_ES_HITS)
        if re.search(r'\bLIMIT\s+\d+', esql_query, re.IGNORECASE):
            query = re.sub(r'\bLIMIT\s+\d+', f'LIMIT {enforced_limit}', esql_query, flags=re.IGNORECASE)
        else:
            query = esql_query.rstrip(";") + f" | LIMIT {enforced_limit}"

        result = await _post("/v1/ai/esql-query", {"query": query})
        output = sanitize_es_result(result)
        audit(tool, params, "allowed", f"rows={len(result) if isinstance(result, list) else '?'}")
        return output
    except GuardrailError as e:
        audit(tool, params, "blocked", str(e))
        return f"[BLOCKED] {e}"
    except Exception as e:
        audit(tool, params, "error", str(e))
        return f"[ERROR] {e}"


# ── Tool: get_field_mappings ───────────────────────────────────────────────────

@mcp.tool()
async def get_field_mappings(index_pattern: str = "logs-*") -> str:
    """
    Return the Elasticsearch field mappings available in an index pattern.
    Use this before drafting a rule to know which ECS fields are actually present.

    Args:
        index_pattern: Elasticsearch index pattern (default: logs-*).

    Returns:
        Dictionary of field names to their types, capped at 150 fields.
    """
    tool = "get_field_mappings"
    params = {"index_pattern": index_pattern}
    try:
        check_rate_limit(tool)
        validate_index_pattern(index_pattern)
        result = await _post("/v1/ai/gather-context", {"type": "ioc", "index_pattern": index_pattern})
        fields = result.get("context", {}).get("field_mappings", {})
        # Cap field count
        if len(fields) > MAX_FIELD_COUNT:
            fields = dict(list(fields.items())[:MAX_FIELD_COUNT])
        output = json.dumps(fields, indent=2)
        audit(tool, params, "allowed", f"fields={len(fields)}")
        return output
    except GuardrailError as e:
        audit(tool, params, "blocked", str(e))
        return f"[BLOCKED] {e}"
    except Exception as e:
        audit(tool, params, "error", str(e))
        return f"[ERROR] {e}"


# ── Tool: search_rules ─────────────────────────────────────────────────────────

@mcp.tool()
async def search_rules(
    query: str = "",
    category: str = "",
    mitre: str = "",
    limit: int = 10,
) -> str:
    """
    Search the SIGMA rule library indexed in Elasticsearch.

    Args:
        query: Free-text search (rule title, description, or field content).
        category: Filter by SIGMA category (e.g. process_creation, network_connection).
        mitre: Filter by MITRE ATT&CK technique ID (e.g. T1059).
        limit: Maximum results to return (default: 10, max: 50).

    Returns:
        Matching rules with title, category, MITRE tags, and a YAML preview.
    """
    tool = "search_rules"
    params = {"query": query, "category": category, "mitre": mitre}
    try:
        check_rate_limit(tool)
        limit = min(max(1, limit), 50)
        result = await _kbn_get("/api/babel/sigma-doc", {
            "search": query, "category": category, "mitre": mitre,
            "from": 0, "size": limit,
        })
        docs = result.get("data", {}).get("docs", [])
        if not docs:
            return "No rules found matching the given criteria."
        lines = [f"Found {len(docs)} rule(s):\n"]
        for doc in docs:
            title = doc.get("title", "Untitled")
            cat   = doc.get("logsource", {}).get("category", "")
            tags  = ", ".join(doc.get("tags", [])[:4])
            lines.append(f"• {title}")
            if cat:   lines.append(f"  Category: {cat}")
            if tags:  lines.append(f"  Tags: {tags}")
            lines.append("")
        audit(tool, params, "allowed", f"results={len(docs)}")
        return "\n".join(lines)
    except GuardrailError as e:
        audit(tool, params, "blocked", str(e))
        return f"[BLOCKED] {e}"
    except Exception as e:
        audit(tool, params, "error", str(e))
        return f"[ERROR] {e}"


# ── Tool: deploy_rule ──────────────────────────────────────────────────────────

@mcp.tool()
async def deploy_rule(
    rule_yaml: str,
    format: str = "eql",
    pipeline: str = "ecs_windows",
    confirm: bool = False,
) -> str:
    """
    Deploy a SIGMA rule to the Kibana detection engine as a live alert rule.

    GUARDRAIL: This tool is DISABLED by default. Set SIGMA_MCP_ALLOW_DEPLOY=true
    in the MCP server environment to enable it.

    CONFIRM: You must pass confirm=True to actually deploy. Without it, a dry-run
    preview is returned showing what would be deployed.

    Args:
        rule_yaml: Complete SIGMA rule as YAML text.
        format: Query format to convert to before deploying (default: eql).
        pipeline: Field-mapping pipeline (default: ecs_windows).
        confirm: Must be True to execute the deployment (default: False = dry run).

    Returns:
        Deployment result with Kibana rule ID, or a dry-run preview.
    """
    tool = "deploy_rule"
    params = {"format": format, "pipeline": pipeline, "confirm": confirm}
    try:
        check_rate_limit(tool)
        check_deploy_allowed()       # env-variable gate
        validate_sigma_input(rule_yaml)

        if not confirm:
            # Dry-run: validate + convert but don't deploy
            validation = await _post("/v1/rules/validate", {"rule_yaml": rule_yaml})
            conversion = await _post("/v1/conversions", {
                "rule_yaml": rule_yaml, "format": format, "pipeline": pipeline,
            })
            query = conversion.get("query_result", "")
            issues = validation.get("issues", [])
            issue_text = "\n".join(f"  [{i['type']}] {i['message']}" for i in issues) if issues else "  None"
            audit(tool, params, "allowed", "dry-run")
            return (
                f"DRY RUN — pass confirm=True to actually deploy.\n\n"
                f"Validation issues:\n{issue_text}\n\n"
                f"Converted query ({format}):\n{query[:2000]}"
            )

        result = await _kbn_post("/api/babel/deploy", {
            "ruleYaml": rule_yaml, "format": format, "pipeline": pipeline,
            "enabled": False,  # always deploy disabled; analyst enables manually
        })
        audit(tool, params, "allowed", "deployed")
        data = result.get("data", result)
        return (
            f"✓ Rule deployed (disabled — enable it manually in Kibana).\n"
            f"Kibana rule ID: {data.get('rule_id', '?')}\n"
            f"Title: {data.get('name', '?')}"
        )
    except GuardrailError as e:
        audit(tool, params, "blocked", str(e))
        return f"[BLOCKED] {e}"
    except Exception as e:
        audit(tool, params, "error", str(e))
        return f"[ERROR] {e}"


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()  # stdio transport — used by Claude Code and Claude Desktop
