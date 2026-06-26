# sigma_ai — Build History

## Overview

sigma_ai is a SIGMA detection engineering platform built as a Kibana plugin with a Python FastAPI backend and an MCP orchestration layer. This document captures the full build history from initial phases through Tier 2 AI-assisted engineering.

---

## Phase 1 — Core Conversion & Backtesting

**What was built:**
- Python FastAPI backend (`server/api/`) at port 8000
- pySigma-powered rule conversion to EQL, ES|QL, Lucene, Kibana NDJSON
- Live backtesting against Elasticsearch — hit count, sample events, timing
- Kibana plugin shell with YAML editor, visual editor, and conversion panel
- GitHub-based rule sync (`/api/babel/sync`)
- Kibana Detection Engine deployment (`/api/sigma_ui/deploy`)
- Watcher creation (`/api/sigma_ui/sigma-add-watcher`)

**Key files established:**
- `server/api/services/conversion.py` — pySigma subprocess wrapper
- `server/api/services/testing.py` — ES query execution (EQL, ES|QL, Lucene)
- `server/routes/sigma_deploy.ts` — Kibana Detection Engine integration
- `public/components/YamlEditor.tsx`, `ConversionPanel.tsx`, `VisualEditor.tsx`

---

## Phase 2 — ECS Field Mapping, Validation, Clustering, Coverage

**What was built:**
- ECS field mapping service — 80+ static SIGMA→ECS mappings + live ES `/_mapping` introspection with 5-min cache
- pySigma rule validation — 8 validators, graceful degradation if pySigma unavailable
- Hit clustering — terms aggregation on 10 ECS fields post-backtest, for exclusion candidate identification
- ATT&CK coverage computation — 14 tactics, ~100 technique names parsed from `attack.t{id}` tags
- Frontend: Validate button + error/warning callouts in YamlEditor; Cluster Hits accordion in ConversionPanel

**New endpoints:**
- `GET /v1/fields` — ECS field catalog browser
- `POST /v1/fields/suggest` — fuzzy field mapping suggestion
- `POST /v1/rules/validate` — pySigma validator chain
- `POST /v1/test-runs/{id}/cluster-hits` — terms aggregation on hit results
- `POST /v1/coverage` — ATT&CK coverage from rule YAML array

**Key files:**
- `server/api/services/fields.py`, `validation.py`, `coverage.py`
- `server/routes/sigma_fields.ts`, `sigma_validate.ts`, `sigma_coverage.ts`

---

## Phase 3 — MCP Hardening (Multi-Tenancy, Auth, Encryption, Migrations)

**What was built:**
- Full MCP platform rewrite: FastAPI + Celery + Redis + PostgreSQL at port 8001
- Multi-tenant model — `Tenant`, `ApiKey`, `AuditLog` tables; all CRUD scoped by `tenant_id`
- API key auth — `{prefix}.{secret}` format; prefix stored plaintext for O(1) lookup, full key bcrypt-hashed
- AES-GCM secrets encryption — `SECRETS_KEY` env var (base64 32 bytes), `mcp/api/crypto.py`
- Alembic migrations — replaces `create_all`; migration 001 handles fresh + existing DBs
- Bootstrap seeding — `BOOTSTRAP_TENANT` + `BOOTSTRAP_API_KEY` env vars
- Prometheus metrics — `prometheus-fastapi-instrumentator`, `/metrics` endpoint
- Worker secrets isolation — API resolves + decrypts secrets at dispatch time; worker receives `resolved_auth_headers` only
- Proxy routes: MCP exposes `/v1/status`, `/v1/fields`, `/v1/fields/suggest`, `/v1/rules/validate`, `/v1/coverage`

**Key files:**
- `mcp/api/crypto.py`, `auth.py`, `crud.py`, `models.py`
- `mcp/api/alembic/versions/001_initial_schema.py`
- `mcp/worker/tasks.py` — updated to receive pre-resolved auth headers

---

## Pre-Tier Audit — 7 Bugs Fixed

Before building features, a full cross-chat audit identified and fixed:

| # | Bug | Fix |
|---|---|---|
| 1 | `EmailStr` import crashed MCP API on startup | Removed unused import |
| 2 | `AllOfThemModifierValidator` doesn't exist in pySigma | Removed from validator list |
| 3 | MCP `TestRunRequest` missing `pipeline` + `query_format` | Added both fields with defaults |
| 4 | Worker task not passing `pipeline`/`query_format` | Now passed explicitly |
| 5 | `EuiHorizontalRule` imported but never used | Removed |
| 6 | `setDeployEnabled` setter declared but never called | Changed to `const` |
| 7 | No Kibana proxy for `/v1/coverage` | Created `sigma_coverage.ts` + registered route |

---

## Feature Roadmap — Discussion & Sequencing

### Frameworks Considered
- **MITRE ATT&CK** — already integrated via coverage service
- **CIS Controls v8** — added as coverage framework (Tier 3)
- **NIST IR Lifecycle** (Preparation → Detection → Containment → Post-Incident) — added as tagging + readiness reporting (Tiers 1, 3, 4)
- **Security Onion** — explicitly added as a supported platform across all tiers

### Why Multi-Backend Output Was Dropped
Plugin's value is depth in Elasticsearch. pySigma CLI already handles multi-backend export. Adding it to the plugin would dilute the Elastic-native identity.

### Final Sequenced Roadmap

| Tier | Theme | Features |
|---|---|---|
| **1** | Engineering Quality | Stale rule detection, Rule effectiveness tracking, Rule quality scoring, Schema drift detection (+ SO), Detection-as-code CI/CD, Alert → SIGMA lookup (sigma_ai rules only) |
| **2** | AI-Assisted Engineering | Rapid rule drafting from IOCs, AI explain/improve, Elastic Alert → SIGMA draft, Security Onion + Suricata → SIGMA draft |
| **3** | Posture Visibility | ATT&CK Coverage Heatmap, CIS Coverage Panel, ATT&CK Navigator Export, IR Phase Tagging |
| **4** | Workflow Composition | IR Readiness Report, Data source awareness (+ SO log sources), Threat actor/campaign coverage |

**Deprioritised:** Peer review workflow, multi-rule bulk operations, round-trip conversion testing, multi-backend output.

---

## External Research — Three Repositories Evaluated

### 1. elastic/mcp-server-elasticsearch
- **Verdict:** Not integrated — deprecated (superseded by Elastic Agent Builder in ES 9.2+)
- **What it exposed:** `list_indices`, `get_mappings`, `search`, `esql`, `get_shards` via Rust MCP server
- **Impact:** Confirmed our Phase 1 API already implements equivalent functionality natively. Validated `get_mappings` approach for schema drift. No Security/SIEM APIs — detection engine not covered.

### 2. elastic/elastic-agent
- **Verdict:** Not integrated — data collection agent, not a detection platform
- **Impact:** Only future relevance: if "auto-configure log collection when coverage gaps detected" is added (Tier 4+), Fleet/Agent becomes relevant. Out of scope now.

### 3. elastic/elasticsearch-labs — Agent Builder notebook
- **Verdict:** Directly informed Tier 2 architecture
- **Key finding:** Exact API format for Kibana Agent Builder — `POST /api/agent_builder/agents` with `id`, `name`, `configuration.instructions`, `configuration.tools[].tool_ids` using `platform.core.*` namespaced tool IDs
- **Impact:** Three persistent Kibana Agent Builder agents defined in `sigma_agent_builder.ts`; Agent Builder tool-access pattern replicated natively in `ai_context.py` for programmatic LLM calls

---

## Tier 1 — Engineering Quality

### Effectiveness Tracking + Stale Detection + Quality Scoring
**Persistence layer:** `.sigma-effectiveness` ES index (hidden index convention)

- Every test run now records a document: `rule_title`, `hit_count`, `ran_at`, `index_pattern`, `query_format`
- Stale rules: aggregation query finds rules with zero hits in a configurable look-back window (default 30 days)
- Quality score (0–100): composite deduction from validation errors (−20 each), warnings (−5 each), never tested (−20), stale (−10/−20), last run 0 hits (−10)
- Score displayed as colour-coded `Q: 84` badge in YamlEditor, auto-fetched after validation

**New files:** `services/effectiveness.py`, `routes/effectiveness.py`  
**Modified:** `routes/test_runs.py` — auto-records effectiveness after every test run

### Schema Drift Detection
**Persistence layer:** `.sigma-schema-snapshots` ES index

- Snapshots ES field mappings for any index pattern; stored with `index_pattern` as doc ID (latest wins)
- Drift report: compares current `/_mapping` against snapshot, reports `removed` or `type_changed` fields
- Security Onion support built-in: `snapshot_all_so()` covers `so-alert-*`, `so-logs-*`, `so-import-*`
- Dedicated SO snapshot endpoint: `POST /api/sigma_ui/schema-drift/snapshot/so`

**New files:** `services/schema_drift.py`, `routes/schema_drift.py`, `server/routes/sigma_schema_drift.ts`

### Alert → SIGMA Lookup (Phase A — sigma_ai rules only)
**Persistence layer:** `.sigma-rule-registry` ES index, keyed by Kibana rule ID

- Deploy route auto-registers source SIGMA YAML on every successful deployment (fire-and-forget, non-fatal)
- `GET /v1/rules/source?kibana_rule_id=X` returns the original YAML for any sigma_ai-deployed rule
- Foundation for Phase B (LLM-powered reverse for any alert) in Tier 2

**New files:** `services/rule_registry.py`, `routes/rule_registry.py`, `server/routes/sigma_rule_registry.ts`  
**Modified:** `server/routes/sigma_deploy.ts` — auto-registers after deploy

### Detection-as-Code CI/CD
`.github/workflows/sigma-validate.yml` — two jobs:
- **validate** (on PR): runs `sigma check` + dry-run EQL conversion on all changed `.yml` files in `rules/`
- **deploy** (on merge to main, `production` environment): deploys changed rules via `POST /api/sigma_ui/deploy` using `SIGMA_AI_URL` + `SIGMA_AI_KEY` GitHub secrets

---

## Tier 2 — AI-Assisted Engineering

### Architecture Decision
Rather than depending on the deprecated Elastic MCP server or the Kibana Agent Builder runtime, Tier 2 uses:
- **Direct Anthropic Claude API** (`claude-sonnet-4-6`) from the Python backend — controlled prompt engineering, no Kibana version dependency
- **Native ES context gathering** before every LLM call — replicates the Agent Builder `get_index_mapping` + `search` + `get_document_by_id` tool pattern
- **Kibana Agent Builder** for persistent chat agents — supplementary UI-layer agents using the exact notebook API format, created via `POST /api/sigma_ui/agent-builder/setup`

### AI Context Service (`ai_context.py`)
Gathers live ES context before LLM calls:
- `gather_ioc_context()` — field mappings + multi-match sample events for IOC-driven drafting
- `gather_alert_context()` — fetches Kibana security alert from `.alerts-security.alerts-default`
- `gather_so_alert_context()` — fetches SO alert from `so-alert-*`; auto-detects source type (suricata/sigma/zeek) from `rule.sid`, `rule.uuid`, `event.module`
- `list_recent_alerts()` — sorted by timestamp for alert picker UI

### AI Generator Service (`ai_generator.py`)
Five Claude-powered capabilities, each with a purpose-built system prompt:

| Method | Input | Output |
|---|---|---|
| `draft_from_iocs()` | IOC list + ES context | SIGMA YAML |
| `explain_rule()` | Rule YAML | Structured plain-English explanation |
| `improve_rule()` | Rule YAML + ES context | Improved YAML + `---CHANGES---` section |
| `draft_from_alert()` | Kibana alert doc + field mappings | SIGMA YAML |
| `draft_from_so_alert()` | SO/Suricata alert doc + source type | Host-level SIGMA YAML |

### Kibana Agent Builder — Three Persistent Agents
Created via `POST /api/sigma_ui/agent-builder/setup`:

| Agent ID | Tools | Purpose |
|---|---|---|
| `sigma-ai-ioc-drafter` | search, get_index_mapping, list_indices, execute_esql | IOC → SIGMA with live ES field context |
| `sigma-ai-alert-converter` | search, get_index_mapping, get_document_by_id, execute_esql | Alert → SIGMA (Kibana + SO) |
| `sigma-ai-rule-advisor` | search, get_index_mapping, list_indices, generate_esql | Explain + improve rules |

### Frontend — AI Assistant Panel (`AiPanel.tsx`)
Flyout accessible via "AI Assistant" in TopNav. Four tabs:

- **IOC → Rule** — multiline IOC input, logsource category hint selector, "Draft Rule" button
- **Alert → Rule** — source selector (Kibana Security / Security Onion), live alert picker with severity badges and event module tags, "Draft Rule from Alert"
- **Explain** — explains rule currently in YAML editor; structured output with ATT&CK, false positives, tuning suggestions
- **Improve** — improves current rule against live field mappings; shows improved YAML + changes accordion

Footer "Load into Editor" button loads generated YAML directly into the main editor.

### New Endpoints (Tier 2)

| Method | Path | Description |
|---|---|---|
| POST | `/v1/ai/draft-from-iocs` | IOC list → SIGMA draft |
| POST | `/v1/ai/explain` | Rule YAML → explanation |
| POST | `/v1/ai/improve` | Rule YAML → improved rule + changes |
| POST | `/v1/ai/draft-from-alert` | Alert ID → SIGMA draft (Kibana or SO) |
| GET | `/v1/ai/alerts` | List recent alerts for picker UI |
| POST | `/api/sigma_ui/agent-builder/setup` | Create Kibana Agent Builder agents |
| DELETE | `/api/sigma_ui/agent-builder/teardown` | Remove Agent Builder agents |

**Prerequisite:** `ANTHROPIC_API_KEY` environment variable on the Python API server.

---

## Current State Summary

| Layer | Status |
|---|---|
| Python FastAPI (port 8000) | Phase 1–2 complete + Tier 1–2 additions |
| MCP Platform (port 8001) | Phase 3 hardened — multi-tenant, encrypted, Alembic |
| Kibana Plugin (server routes) | All tiers proxied |
| Frontend | YamlEditor + ConversionPanel + AI Assistant Panel |
| CI/CD | GitHub Actions validate + deploy workflow |
| ES Indices | `.sigma-effectiveness`, `.sigma-schema-snapshots`, `.sigma-rule-registry` |

---

## ⚠️ Tier 3 — Posture Visibility `[NOT STARTED]`

> These features describe the detection posture of the environment. They consume outputs from Tiers 1 and 2 — coverage data, IR phase tags, and rule effectiveness — and surface them as visual reports. No code has been written for any Tier 3 feature.

### 11. ATT&CK Coverage Heatmap UI
**What:** Frontend panel rendering a MITRE ATT&CK matrix heatmap coloured by rule coverage density. Techniques with multiple rules are darker; uncovered techniques are grey.  
**Backend dependency:** `POST /v1/coverage` already exists and returns `techniques`, `by_tactic`, `covered_techniques`, `uncovered_tactics`. No new backend work required.  
**Frontend work needed:**
- New `CoverageHeatmap` component — renders a grid of tactic columns × technique rows
- Colour scale mapped to `rules.length` per technique bucket
- Tooltip showing rule titles on hover
- Wire into a new "Coverage" page/tab accessible from TopNav

### 12. CIS Coverage Panel
**What:** Same heatmap mechanic as ATT&CK but indexed against CIS Controls v8 — 18 controls and their safeguards. Shows which safeguards have detection coverage and which are gaps.  
**Backend work needed:**
- New `services/cis_coverage.py` — static mapping of SIGMA rule logsource categories and detection keywords to CIS safeguard IDs (e.g., logsource `antivirus` → CIS 10; `network` → CIS 13; `audit_log` → CIS 8)
- `POST /v1/cis-coverage` — accepts rule YAMLs, returns coverage per safeguard
- Kibana proxy route: `POST /api/sigma_ui/cis-coverage`  
**Frontend work needed:**
- `CisCoveragePanel` component — grid of 18 controls with safeguard-level drill-down
- Same colour-scale pattern as ATT&CK heatmap

### 13. ATT&CK Navigator Export
**What:** Generates a valid MITRE ATT&CK Navigator layer JSON file from the existing coverage data. Users can import it into the Navigator for stakeholder reporting.  
**Backend work needed:**
- `GET /v1/coverage/navigator-export` — serialises coverage output into Navigator layer format (`{ "version": "4.5", "techniques": [...], "gradient": {...} }`)
- Kibana proxy route: `GET /api/sigma_ui/coverage/navigator-export`  
**Frontend work needed:**
- "Export Navigator Layer" download button on the ATT&CK heatmap panel
- Calls the export endpoint and triggers a JSON file download

### 14. IR Phase Tagging
**What:** Lightweight metadata field `x-ir-phase` added to SIGMA rule YAML. Values: `preparation`, `detection`, `containment`, `eradication`, `recovery`, `post-incident`. Displayed as a badge in the rule browser and factored into the IR Readiness Report (Tier 4).  
**Backend work needed:**
- Extend validation service to recognise `x-ir-phase` as a valid custom field (no error on parse)
- Extend rule doc index mapping to store `ir_phase` as a keyword field
- `GET /v1/sigma-doc` response should include `ir_phase` when present  
**Frontend work needed:**
- IR phase badge in rule browser (RuleSelector component)
- IR phase selector in VisualEditor
- IR phase filter in rule search

---

## ⚠️ Tier 4 — Workflow Composition `[NOT STARTED]`

> These features aggregate outputs from all prior tiers into scenario-level tools. They are the most complex features and have the most cross-tier dependencies. No code has been written for any Tier 4 feature.

### 15. IR Readiness Report
**What:** Given a named threat scenario (ransomware, credential theft, insider threat, lateral movement — generic templates), generates a gap report showing which SIGMA rules exist per IR phase and which phases are uncovered.  
**Dependencies:** Requires IR Phase Tagging (Tier 3 #14), ATT&CK coverage data, and CIS coverage data to all be live. Aggregates all three into a single scenario report.  
**Backend work needed:**
- `services/ir_readiness.py` — scenario definitions (YAML templates mapping threat type → expected ATT&CK techniques + IR phases); gap computation against live rule library
- `POST /v1/ir-readiness` — accepts scenario name, returns phase-by-phase gap report
- Kibana proxy route: `POST /api/sigma_ui/ir-readiness`  
**Frontend work needed:**
- `IrReadinessPanel` component — scenario selector dropdown, phase-by-phase coverage swimlane, gap callouts with "create rule" shortcuts

### 16. Data Source Awareness
**What:** Introspects live ES index patterns to determine which log sources are actually present in the environment, then maps them to SIGMA logsource categories. Identifies rules whose logsource has no matching data in the cluster. Explicitly covers Security Onion log sources.  
**SO log sources covered:**
- Zeek: `conn.log`, `dns.log`, `http.log`, `ssl.log`, `weird.log` → `zeek_*` SIGMA categories
- Suricata alerts → `network` / `firewall` categories
- Syslog → `linux` / `syslog` categories  
**Backend work needed:**
- `services/data_sources.py` — `GET /_cat/indices` introspection; maps index name patterns to SIGMA logsource categories; identifies rules with no matching data source
- `GET /v1/data-sources` — returns available logsources + coverage status
- `GET /v1/data-sources/gaps` — rules whose logsource has no live data
- Kibana proxy routes  
**Frontend work needed:**
- Data source awareness panel showing: available sources (green), missing sources (red), affected rules per gap
- "Snapshot SO schemas" shortcut button (calls existing Tier 1 endpoint)

### 17. Threat Actor / Campaign Coverage
**What:** Maps the rule library against known threat actor profiles and campaigns using ATT&CK Groups data. Answers: "Do we have coverage for APT29? What techniques used by Lazarus Group are we missing?"  
**Dependencies:** Requires ATT&CK coverage heatmap (Tier 3 #11) to be solid first — technique coverage is the foundation.  
**Backend work needed:**
- `services/threat_actors.py` — static ATT&CK Groups data (JSON from MITRE CTI repo); maps group → techniques; computes coverage intersection with deployed rules
- `GET /v1/threat-actors` — list of known groups with coverage percentage
- `GET /v1/threat-actors/{group_id}` — technique-level gap report for a specific group
- Kibana proxy routes  
**Frontend work needed:**
- Threat actor browser — searchable list of ATT&CK groups with coverage badges
- Per-group technique gap view with "draft rule" shortcuts into AI Assistant

---

## Current State Summary

| Layer | Status |
|---|---|
| Python FastAPI (port 8000) | Phase 1–2 complete + Tier 1–2 additions |
| MCP Platform (port 8001) | Phase 3 hardened — multi-tenant, encrypted, Alembic |
| Kibana Plugin (server routes) | Tiers 1–2 proxied |
| Frontend | YamlEditor + ConversionPanel + AI Assistant Panel |
| CI/CD | GitHub Actions validate + deploy workflow |
| ES Indices | `.sigma-effectiveness`, `.sigma-schema-snapshots`, `.sigma-rule-registry` |
| Tier 3 — Posture Visibility | ⚠️ Not started |
| Tier 4 — Workflow Composition | ⚠️ Not started |
