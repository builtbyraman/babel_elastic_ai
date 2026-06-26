"""
ECS field mapping service.

Provides two layers:
  - Static: curated Sigma field name → ECS field name catalog
  - Live:   introspects the user's Elasticsearch index mappings via GET /_mapping
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# ── Static Sigma → ECS mapping ────────────────────────────────────────────────

SIGMA_TO_ECS: dict[str, str] = {
    # Process
    "CommandLine":          "process.command_line",
    "Image":                "process.executable",
    "ParentCommandLine":    "process.parent.command_line",
    "ParentImage":          "process.parent.executable",
    "ParentProcessId":      "process.parent.pid",
    "ParentProcessName":    "process.parent.name",
    "ProcessId":            "process.pid",
    "ProcessName":          "process.name",
    "CurrentDirectory":     "process.working_directory",
    "OriginalFileName":     "process.pe.original_file_name",
    "Company":              "process.pe.company",
    "Description":          "process.pe.description",
    "Product":              "process.pe.product",
    "Hashes":               "process.hash.sha256",
    "md5":                  "process.hash.md5",
    "sha1":                 "process.hash.sha1",
    "sha256":               "process.hash.sha256",
    "Imphash":              "process.pe.imphash",
    "User":                 "user.name",
    "IntegrityLevel":       "winlog.event_data.IntegrityLevel",
    "SubjectUserName":      "user.name",
    "SubjectUserSid":       "user.id",
    "SubjectDomainName":    "user.domain",
    "TargetUserName":       "user.target.name",
    "TargetUserSid":        "user.target.id",
    "TargetDomainName":     "user.target.domain",
    # File
    "TargetFilename":       "file.path",
    "SourceFilename":       "file.path",
    "ObjectName":           "file.path",
    "FileName":             "file.name",
    "FileExtension":        "file.extension",
    "FileSize":             "file.size",
    # Network
    "DestinationIp":        "destination.ip",
    "DestinationPort":      "destination.port",
    "DestinationHostname":  "destination.domain",
    "DestinationIsIpv6":    "network.type",
    "SourceIp":             "source.ip",
    "SourcePort":           "source.port",
    "SourceHostname":       "source.domain",
    "Initiated":            "network.direction",
    "Protocol":             "network.protocol",
    "IpAddress":            "source.ip",
    "IpPort":               "source.port",
    "WorkstationName":      "source.domain",
    # DNS
    "QueryName":            "dns.question.name",
    "QueryType":            "dns.question.type",
    "QueryResults":         "dns.answers.data",
    "query":                "dns.question.name",
    # Registry
    "TargetObject":         "registry.path",
    "Details":              "registry.data.strings",
    "NewName":              "registry.path",
    "EventType":            "event.action",
    # Authentication / Windows Events
    "EventID":              "event.code",
    "LogonType":            "winlog.event_data.LogonType",
    "AuthenticationPackageName": "winlog.event_data.AuthenticationPackageName",
    "LmPackageName":        "winlog.event_data.LmPackageName",
    "Channel":              "winlog.channel",
    "Provider_Name":        "winlog.provider_name",
    "Computer":             "host.hostname",
    "Hostname":             "host.hostname",
    # Service
    "ServiceName":          "service.name",
    "ServiceFileName":      "process.executable",
    "StartType":            "winlog.event_data.StartType",
    # HTTP
    "cs-method":            "http.request.method",
    "cs-uri-query":         "url.query",
    "cs-uri-stem":          "url.path",
    "cs-uri":               "url.full",
    "sc-status":            "http.response.status_code",
    "c-useragent":          "user_agent.original",
    "cs-host":              "url.domain",
    "cs-referer":           "http.request.referrer",
    # PowerShell
    "ScriptBlockText":      "powershell.file.script_block_text",
    "Path":                 "file.path",
    "Payload":              "event.original",
    # Named Pipe / WMI
    "PipeName":             "file.name",
    "Operation":            "event.action",
    # Cloud / Azure
    "operationName":        "event.action",
    "resourceType":         "cloud.service.name",
    "callerIpAddress":      "source.ip",
    "identity":             "user.name",
    # Common
    "Message":              "message",
    "Keywords":             "event.category",
    "Severity":             "log.level",
}

# ── ECS catalog organized by category (for field browser) ────────────────────

ECS_CATALOG: dict[str, list[dict]] = {
    "process": [
        {"field": "process.command_line",          "type": "wildcard", "description": "Full command line"},
        {"field": "process.executable",            "type": "keyword",  "description": "Absolute path to the process executable"},
        {"field": "process.name",                  "type": "keyword",  "description": "Process name (basename of executable)"},
        {"field": "process.pid",                   "type": "long",     "description": "Process ID"},
        {"field": "process.working_directory",     "type": "keyword",  "description": "Current working directory"},
        {"field": "process.parent.command_line",   "type": "wildcard", "description": "Parent process command line"},
        {"field": "process.parent.executable",     "type": "keyword",  "description": "Parent process executable path"},
        {"field": "process.parent.name",           "type": "keyword",  "description": "Parent process name"},
        {"field": "process.parent.pid",            "type": "long",     "description": "Parent process ID"},
        {"field": "process.pe.original_file_name", "type": "keyword",  "description": "PE original file name"},
        {"field": "process.pe.company",            "type": "keyword",  "description": "Company name from PE metadata"},
        {"field": "process.hash.sha256",           "type": "keyword",  "description": "SHA-256 hash of the process"},
        {"field": "process.hash.md5",              "type": "keyword",  "description": "MD5 hash of the process"},
    ],
    "file": [
        {"field": "file.path",      "type": "keyword", "description": "Full file path"},
        {"field": "file.name",      "type": "keyword", "description": "File name (basename)"},
        {"field": "file.extension", "type": "keyword", "description": "File extension"},
        {"field": "file.size",      "type": "long",    "description": "File size in bytes"},
        {"field": "file.hash.sha256","type": "keyword","description": "SHA-256 hash of the file"},
        {"field": "file.hash.md5",  "type": "keyword", "description": "MD5 hash of the file"},
    ],
    "network": [
        {"field": "destination.ip",     "type": "ip",      "description": "Destination IP address"},
        {"field": "destination.port",   "type": "long",    "description": "Destination port"},
        {"field": "destination.domain", "type": "keyword", "description": "Destination hostname"},
        {"field": "source.ip",          "type": "ip",      "description": "Source IP address"},
        {"field": "source.port",        "type": "long",    "description": "Source port"},
        {"field": "source.domain",      "type": "keyword", "description": "Source hostname"},
        {"field": "network.protocol",   "type": "keyword", "description": "Network protocol (tcp, udp, etc.)"},
        {"field": "network.direction",  "type": "keyword", "description": "Network direction (ingress/egress)"},
    ],
    "dns": [
        {"field": "dns.question.name", "type": "keyword", "description": "DNS query name"},
        {"field": "dns.question.type", "type": "keyword", "description": "DNS query type (A, AAAA, MX, etc.)"},
        {"field": "dns.answers.data",  "type": "keyword", "description": "DNS answer data"},
    ],
    "registry": [
        {"field": "registry.path",         "type": "keyword", "description": "Full registry key path"},
        {"field": "registry.key",          "type": "keyword", "description": "Registry key name"},
        {"field": "registry.value",        "type": "keyword", "description": "Registry value name"},
        {"field": "registry.data.strings", "type": "wildcard","description": "Registry value data (string)"},
    ],
    "user": [
        {"field": "user.name",        "type": "keyword", "description": "Username"},
        {"field": "user.id",          "type": "keyword", "description": "User SID or unique identifier"},
        {"field": "user.domain",      "type": "keyword", "description": "User's domain"},
        {"field": "user.target.name", "type": "keyword", "description": "Target username (for impersonation)"},
    ],
    "event": [
        {"field": "event.code",     "type": "keyword", "description": "Event ID / code"},
        {"field": "event.action",   "type": "keyword", "description": "Event action (e.g. process-created)"},
        {"field": "event.category", "type": "keyword", "description": "Event category"},
        {"field": "event.type",     "type": "keyword", "description": "Event type"},
        {"field": "event.outcome",  "type": "keyword", "description": "Event outcome (success/failure)"},
    ],
    "host": [
        {"field": "host.hostname", "type": "keyword", "description": "Hostname"},
        {"field": "host.name",     "type": "keyword", "description": "Host name"},
        {"field": "host.os.name",  "type": "keyword", "description": "OS name"},
        {"field": "host.ip",       "type": "ip",      "description": "Host IP addresses"},
    ],
    "http": [
        {"field": "http.request.method",   "type": "keyword", "description": "HTTP method"},
        {"field": "http.response.status_code","type":"long",  "description": "HTTP status code"},
        {"field": "url.full",              "type": "wildcard","description": "Full URL"},
        {"field": "url.path",              "type": "wildcard","description": "URL path"},
        {"field": "url.query",             "type": "keyword", "description": "URL query string"},
        {"field": "url.domain",            "type": "keyword", "description": "URL domain"},
        {"field": "user_agent.original",   "type": "keyword", "description": "User agent string"},
    ],
    "winlog": [
        {"field": "winlog.channel",       "type": "keyword", "description": "Windows event log channel"},
        {"field": "winlog.provider_name", "type": "keyword", "description": "Windows event provider name"},
        {"field": "winlog.event_id",      "type": "long",    "description": "Windows event ID"},
    ],
}

# Reverse index: ECS field → Sigma field (for lookup)
ECS_TO_SIGMA: dict[str, str] = {v: k for k, v in SIGMA_TO_ECS.items()}

# ── Live field cache ──────────────────────────────────────────────────────────

_live_cache: dict[str, tuple[list[str], float]] = {}  # index_pattern → (fields, ts)
_CACHE_TTL = 300  # 5 minutes


class FieldMappingService:

    def get_catalog(self, category: str | None = None) -> dict:
        """Return the static ECS field catalog, optionally filtered by category."""
        if category and category in ECS_CATALOG:
            return {category: ECS_CATALOG[category]}
        return ECS_CATALOG

    def suggest(self, sigma_field: str) -> dict | None:
        """
        Map a Sigma field name to its ECS equivalent.
        Returns { ecs_field, confidence, description } or None if no match found.
        """
        # Exact match
        if sigma_field in SIGMA_TO_ECS:
            ecs_field = SIGMA_TO_ECS[sigma_field]
            desc = self._describe(ecs_field)
            return {"ecs_field": ecs_field, "confidence": 1.0, "description": desc}

        # Case-insensitive match
        lower = sigma_field.lower()
        for k, v in SIGMA_TO_ECS.items():
            if k.lower() == lower:
                return {"ecs_field": v, "confidence": 0.95, "description": self._describe(v)}

        # Partial suffix match (e.g. "Image" inside "ParentImage")
        for k, v in SIGMA_TO_ECS.items():
            if lower in k.lower():
                return {"ecs_field": v, "confidence": 0.6, "description": self._describe(v)}

        return None

    async def get_live_fields(self, index_pattern: str, es_url: str, api_key: str | None = None) -> list[str]:
        """Fetch flat field list from a live Elasticsearch index mapping, cached 5 min."""
        cache_key = f"{es_url}:{index_pattern}"
        if cache_key in _live_cache:
            fields, ts = _live_cache[cache_key]
            if time.time() - ts < _CACHE_TTL:
                return fields

        headers: dict[str, str] = {"Accept": "application/json"}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"{es_url}/{index_pattern}/_mapping", headers=headers)
                resp.raise_for_status()
        except Exception as e:
            logger.warning(f"Live field fetch failed for {index_pattern}: {e}")
            return []

        fields = _flatten_mapping(resp.json())
        _live_cache[cache_key] = (fields, time.time())
        return fields

    def _describe(self, ecs_field: str) -> str:
        for entries in ECS_CATALOG.values():
            for e in entries:
                if e["field"] == ecs_field:
                    return e["description"]
        return ""


def _flatten_mapping(mapping_response: dict) -> list[str]:
    """Flatten an ES _mapping response into a sorted list of dotted field names."""
    fields: set[str] = set()
    for index_data in mapping_response.values():
        props = index_data.get("mappings", {}).get("properties", {})
        _walk(props, "", fields)
    return sorted(fields)


def _walk(props: dict, prefix: str, out: set[str]) -> None:
    for name, meta in props.items():
        full = f"{prefix}{name}"
        out.add(full)
        if "properties" in meta:
            _walk(meta["properties"], f"{full}.", out)
