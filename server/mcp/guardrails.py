"""
MCP guardrails for sigma-ai.

All tool inputs pass through here before reaching sigma-api or Elasticsearch.
Guardrail categories:
  1. Input validation   — reject malformed or out-of-range parameters
  2. Scope restriction  — block write operations, system indices, blocked patterns
  3. Rate limiting      — cap call frequency per tool to prevent runaway agent loops
  4. Result sanitization— strip sensitive fields, truncate large payloads
  5. Audit logging      — every call (allowed or blocked) written to audit log
"""

import json
import logging
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
audit_logger = logging.getLogger("sigma_mcp.audit")

# ── Audit log setup ────────────────────────────────────────────────────────────

_AUDIT_LOG_PATH = Path(__file__).parent / "audit.log"

def _setup_audit_log() -> None:
    handler = logging.FileHandler(_AUDIT_LOG_PATH)
    handler.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False

_setup_audit_log()


def audit(tool: str, params: dict, outcome: str, detail: str = "") -> None:
    """Write a structured audit record."""
    record = {
        "ts":      datetime.now(timezone.utc).isoformat(),
        "tool":    tool,
        "params":  _sanitize_params(params),
        "outcome": outcome,  # "allowed" | "blocked" | "error"
        "detail":  detail,
    }
    audit_logger.info(json.dumps(record))


def _sanitize_params(params: dict) -> dict:
    """Redact values whose keys look like credentials before logging."""
    SENSITIVE_KEYS = re.compile(r'(key|secret|token|password|credential|auth)', re.I)
    return {
        k: "***REDACTED***" if SENSITIVE_KEYS.search(k) else (
            v[:120] + "…" if isinstance(v, str) and len(v) > 120 else v
        )
        for k, v in params.items()
    }


# ── Rate limiter ───────────────────────────────────────────────────────────────

# Maps tool name → (max_calls, window_seconds)
RATE_LIMITS: dict[str, tuple[int, int]] = {
    "query_elasticsearch": (15, 60),   # ES queries: 15/min — prevent runaway loops
    "deploy_rule":         (5,  60),   # Deployments: 5/min — destructive-ish
    "test_rule":           (20, 60),
    "_default":            (60, 60),   # All other tools: 60/min
}

_call_history: dict[str, list[float]] = defaultdict(list)


def check_rate_limit(tool: str) -> None:
    """Raise GuardrailError if the tool has exceeded its rate limit."""
    max_calls, window = RATE_LIMITS.get(tool, RATE_LIMITS["_default"])
    now = time.monotonic()
    history = _call_history[tool]
    # Prune calls outside the window
    _call_history[tool] = [t for t in history if now - t < window]
    if len(_call_history[tool]) >= max_calls:
        raise GuardrailError(
            f"Rate limit exceeded for '{tool}': max {max_calls} calls per {window}s. "
            "Slow down — you may be in an unintended agent loop."
        )
    _call_history[tool].append(now)


# ── ES|QL scope restriction ────────────────────────────────────────────────────

# ES|QL write operations the model must never issue
_ESQL_WRITE_RE = re.compile(
    r'\b(DELETE|PUT|POST|REINDEX|UPDATE|CREATE|DROP|TRUNCATE|INSERT)\b',
    re.IGNORECASE,
)

# System / sensitive index prefixes — never allow querying these
_BLOCKED_INDEX_PREFIXES = (
    ".kibana", ".security", ".fleet", ".internal", ".async",
    ".siem-signals", ".alerts", "audit-"
)

# Fields to redact from ES results before returning to the LLM
_SENSITIVE_FIELD_RE = re.compile(
    r'(password|passwd|secret|token|api_key|credential|auth_token|bearer|private_key)',
    re.IGNORECASE,
)

MAX_ES_RESULT_CHARS = 10_000   # truncate ES results beyond this
MAX_ES_HITS        = 50        # cap on rows returned to LLM
MAX_FIELD_COUNT    = 150       # cap on field mapping entries


def validate_esql(query: str) -> None:
    """Reject ES|QL queries that contain write operations."""
    if _ESQL_WRITE_RE.search(query):
        raise GuardrailError(
            "ES|QL query contains a write operation (DELETE/PUT/UPDATE/etc.). "
            "Only read queries are permitted."
        )


def validate_index_pattern(pattern: str) -> None:
    """Reject requests targeting system or sensitive indices."""
    lower = pattern.lower()
    for prefix in _BLOCKED_INDEX_PREFIXES:
        if lower.startswith(prefix) or lower == prefix.lstrip("."):
            raise GuardrailError(
                f"Index pattern '{pattern}' targets a restricted system index. "
                "Only user-space indices (logs-*, winlogbeat-*, so-*, etc.) are permitted."
            )


def sanitize_es_result(result: Any) -> str:
    """
    Redact sensitive field values and truncate large result payloads
    before returning them to the LLM context window.
    """
    text = json.dumps(result, default=str)

    # Redact sensitive values
    def _redact(m: re.Match) -> str:
        return m.group(0)  # keep key; value is handled below

    # Simple key-based redaction in JSON: "password": "..." → "password": "***"
    text = re.sub(
        r'("(?:' + _SENSITIVE_FIELD_RE.pattern + r')":\s*)"[^"]*"',
        r'\1"***REDACTED***"',
        text,
        flags=re.IGNORECASE,
    )

    if len(text) > MAX_ES_RESULT_CHARS:
        text = text[:MAX_ES_RESULT_CHARS] + f"\n… [truncated — {len(text)} chars total]"

    return text


# ── SIGMA YAML validation ──────────────────────────────────────────────────────

def validate_sigma_input(yaml_text: str) -> None:
    """Reject obviously empty or non-SIGMA input before it reaches the API."""
    if not yaml_text or not yaml_text.strip():
        raise GuardrailError("rule_yaml is empty.")
    if len(yaml_text) > 50_000:
        raise GuardrailError("rule_yaml exceeds 50 KB — suspiciously large input rejected.")
    if not any(k in yaml_text for k in ("title:", "detection:", "logsource:")):
        raise GuardrailError(
            "Input does not appear to be a SIGMA rule — missing title/detection/logsource."
        )


# ── Parameter range guards ─────────────────────────────────────────────────────

def validate_timeframe(hours: int) -> None:
    if not (1 <= hours <= 168):
        raise GuardrailError("timeframe_hours must be between 1 and 168 (1 week).")


def validate_limit(limit: int) -> None:
    if not (1 <= limit <= MAX_ES_HITS):
        raise GuardrailError(f"limit must be between 1 and {MAX_ES_HITS}.")


# ── Deployment gate ────────────────────────────────────────────────────────────

_DEPLOY_ENABLED_ENV = "SIGMA_MCP_ALLOW_DEPLOY"

def check_deploy_allowed() -> None:
    """Block deploy_rule unless explicitly opted-in via environment variable."""
    import os
    if os.getenv(_DEPLOY_ENABLED_ENV, "").lower() not in ("1", "true", "yes"):
        raise GuardrailError(
            "deploy_rule is disabled by default. "
            f"Set {_DEPLOY_ENABLED_ENV}=true in the MCP server environment to enable it."
        )


# ── Central error type ─────────────────────────────────────────────────────────

class GuardrailError(Exception):
    """Raised when any guardrail check fails. Message is returned to the LLM."""
