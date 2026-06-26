"""
AI-assisted detection engineering routes.

Endpoints:
- POST /v1/ai/draft-from-iocs      — IOC list → SIGMA rule draft
- POST /v1/ai/explain              — plain-English rule explanation
- POST /v1/ai/improve              — LLM-improved rule + change summary
- POST /v1/ai/draft-from-alert     — Kibana or SO alert → SIGMA rule draft
- GET  /v1/ai/alerts               — list recent alerts for the picker UI
- POST /v1/ai/gather-context       — context-only (field mappings + events); used by Kibana connector mode
"""

from fastapi import APIRouter, Depends, Query, Request
from schemas.models import (
    AIDraftFromIOCsRequest, AIExplainRequest, AIImproveRequest,
    AIAlertDraftRequest, AIResultResponse, AlertListResponse, AlertSummary,
    AIChatRequest, AIChatResponse,
)
from services.ai_context import AIContextService
from services.ai_generator import AIGeneratorService, PROVIDER_ANTHROPIC
from services.url_fetcher import extract_urls, fetch_url_text
from config import get_settings, Settings, make_es_client
import asyncio
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


def _llm_params(request: Request) -> dict:
    """Extract LLM provider params forwarded as request headers by the Kibana plugin."""
    return {
        "provider":  request.headers.get("x-llm-provider", "") or PROVIDER_ANTHROPIC,
        "api_key":   request.headers.get("x-anthropic-api-key", "") or request.headers.get("x-llm-api-key", "") or None,
        "base_url":  request.headers.get("x-llm-base-url", "") or None,
        "model":     request.headers.get("x-llm-model", "") or None,
    }


@router.post("/ai/draft-from-iocs", response_model=AIResultResponse)
async def draft_from_iocs(
    body: AIDraftFromIOCsRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
):
    p = _llm_params(request)
    ctx_svc = AIContextService(settings)
    gen_svc = AIGeneratorService()
    context = await ctx_svc.gather_ioc_context(iocs=body.iocs, index_pattern=body.index_pattern)
    return AIResultResponse(**(await gen_svc.draft_from_iocs(
        iocs=body.iocs, context=context, logsource_hint=body.logsource_hint, **p,
    )))


@router.post("/ai/explain", response_model=AIResultResponse)
async def explain_rule(body: AIExplainRequest, request: Request):
    p = _llm_params(request)
    gen_svc = AIGeneratorService()
    return AIResultResponse(**(await gen_svc.explain_rule(body.rule_yaml, **p)))


@router.post("/ai/improve", response_model=AIResultResponse)
async def improve_rule(
    body: AIImproveRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
):
    p = _llm_params(request)
    ctx_svc = AIContextService(settings)
    gen_svc = AIGeneratorService()
    context = await ctx_svc.gather_ioc_context(iocs=[], index_pattern=body.index_pattern)
    return AIResultResponse(**(await gen_svc.improve_rule(body.rule_yaml, context, **p)))


@router.post("/ai/draft-from-alert", response_model=AIResultResponse)
async def draft_from_alert(
    body: AIAlertDraftRequest,
    request: Request,
    settings: Settings = Depends(get_settings),
):
    p = _llm_params(request)
    ctx_svc = AIContextService(settings)
    gen_svc = AIGeneratorService()
    if body.source == "so":
        context = await ctx_svc.gather_so_alert_context(body.alert_id)
        return AIResultResponse(**(await gen_svc.draft_from_so_alert(context, **p)))
    else:
        context = await ctx_svc.gather_alert_context(body.alert_id)
        return AIResultResponse(**(await gen_svc.draft_from_alert(context, **p)))


@router.post("/ai/esql-query")
async def esql_query(
    request: Request,
    settings: Settings = Depends(get_settings),
):
    """
    Execute a read-only ES|QL query via the sigma-api ES client.
    Called by the MCP server's query_elasticsearch tool.
    """
    body = await request.json()
    query = body.get("query", "").strip()
    if not query:
        return {"error": "query is required"}
    try:
        # Reuse the shared sync client (basic-auth / api-key aware) off the event
        # loop — avoids an aiohttp dependency just for ES|QL.
        api_key = getattr(request.state, "elastic_api_key", "") or None
        es = make_es_client(settings, api_key)

        def _run():
            try:
                return es.esql.query(query=query)
            finally:
                es.close()

        resp = await asyncio.to_thread(_run)
        return {"success": True, "result": resp.body if hasattr(resp, "body") else dict(resp)}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.post("/ai/gather-context")
async def gather_context(
    request: Request,
    settings: Settings = Depends(get_settings),
):
    """
    Return raw context (field mappings + sample events) without calling the LLM.
    Used by Kibana connector mode: Kibana gathers context here, builds the prompt,
    then executes the inference via an Elastic connector.
    """
    body = await request.json()
    ctx_type = body.get("type", "ioc")
    ctx_svc = AIContextService(settings)

    if ctx_type == "alert":
        alert_id = body.get("alert_id", "")
        source = body.get("source", "kibana")
        if source == "so":
            context = await ctx_svc.gather_so_alert_context(alert_id)
        else:
            context = await ctx_svc.gather_alert_context(alert_id)
    else:
        index_pattern = body.get("index_pattern", "logs-*")
        context = await ctx_svc.gather_ioc_context(iocs=[], index_pattern=index_pattern)

    return {"success": True, "context": context}


@router.post("/ai/chat", response_model=AIChatResponse)
async def chat(body: AIChatRequest, request: Request):
    p = _llm_params(request)
    gen_svc = AIGeneratorService()

    messages = [{"role": m.role, "content": m.content} for m in body.messages]

    # URL enrichment: detect URLs in the last user message and inject fetched content
    if messages and messages[-1]["role"] == "user":
        last_content = messages[-1]["content"]
        urls = extract_urls(last_content)[:2]  # cap at 2 URLs per turn
        if urls:
            url_blocks: list[str] = []
            for url in urls:
                text = fetch_url_text(url)
                if text:
                    url_blocks.append(f"[Content fetched from {url}]\n{text}")
            if url_blocks:
                enriched = "\n\n".join(url_blocks) + "\n\n" + last_content
                messages = messages[:-1] + [{"role": "user", "content": enriched}]

    result = await gen_svc.chat(
        messages=messages,
        rule_context=body.rule_context,
        **p,
    )
    return AIChatResponse(**result)


@router.get("/ai/alerts", response_model=AlertListResponse)
async def list_alerts(
    source: str = Query(default="kibana", description="'kibana' or 'so'"),
    size: int = Query(default=20, ge=1, le=100),
    settings: Settings = Depends(get_settings),
):
    ctx_svc = AIContextService(settings)
    index_pattern = (
        "so-alert-*" if source == "so"
        else ".alerts-security.alerts-default"
    )
    raw = await ctx_svc.list_recent_alerts(index_pattern=index_pattern, size=size)

    alerts = []
    for doc in raw:
        alerts.append(AlertSummary(
            id=doc.get("_id", ""),
            timestamp=doc.get("@timestamp"),
            rule_name=(
                doc.get("kibana.alert.rule.name")
                or doc.get("rule", {}).get("name")
                or doc.get("rule.name")
            ),
            severity=(
                doc.get("kibana.alert.severity")
                or doc.get("event", {}).get("severity")
            ),
            host_name=doc.get("host", {}).get("name") or doc.get("host.name"),
            event_module=doc.get("event", {}).get("module") or doc.get("event.module"),
        ))

    return AlertListResponse(alerts=alerts, index_pattern=index_pattern)
