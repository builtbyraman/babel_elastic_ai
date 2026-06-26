import { IRouter } from '@kbn/core/server';
import { schema } from '@kbn/config-schema';
import { PluginConfig } from '../config';
import { readAnthropicKey } from './anthropic_key';
import { readAiProviderConfig, providerHeaders } from './ai_provider';

const SIGMA_API_KEY = process.env.SIGMA_API_KEY || '';

function sigmaAuthHeader(): Record<string, string> {
  return SIGMA_API_KEY ? { authorization: `Bearer ${SIGMA_API_KEY}` } : {};
}

async function proxyPost(url: string, body: unknown, extraHeaders: Record<string, string> = {}) {
  return fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...sigmaAuthHeader(), ...extraHeaders },
    body: JSON.stringify(body),
  });
}

/** Read full provider config + Anthropic key, return combined header map for sigma-api. */
async function buildLlmHeaders(context: any): Promise<Record<string, string>> {
  const [cfg, anthropicKey] = await Promise.all([
    readAiProviderConfig(context),
    readAnthropicKey(context),
  ]);
  return providerHeaders(cfg, anthropicKey);
}

export function registerSigmaAIRoutes(router: IRouter, config: PluginConfig): void {
  const SIGMA_API_URL = config.sigmaApiUrl;

  // ── draft-from-iocs ──────────────────────────────────────────────────────────
  router.post({
    path: '/api/babel/ai/draft-from-iocs',
    options: { access: 'public' },
    security: { authz: { enabled: false, reason: 'AI draft; LLM key managed server-side' } },
    validate: {
      body: schema.object({
        iocs:           schema.arrayOf(schema.string()),
        indexPattern:   schema.maybe(schema.string()),
        logsourceHint:  schema.maybe(schema.string()),
      }),
    },
  }, async (ctx, request, response) => {
    const { iocs, indexPattern, logsourceHint } = request.body as any;
    const cfg = await readAiProviderConfig(ctx);

    if (cfg.provider === 'connector') {
      return proxyToConnector(ctx, request, response, {
        action: 'draft-from-iocs', iocs, index_pattern: indexPattern, logsource_hint: logsourceHint,
      });
    }

    const llmHeaders = await buildLlmHeaders(ctx);
    try {
      const res = await proxyPost(`${SIGMA_API_URL}/ai/draft-from-iocs`, {
        iocs, index_pattern: indexPattern ?? 'logs-*', logsource_hint: logsourceHint,
      }, llmHeaders);
      const body = await res.json().catch(() => null);
      return res.ok ? response.ok({ body }) : response.customError({ statusCode: res.status, body: { message: body?.message ?? 'AI draft failed' } });
    } catch (err: unknown) {
      return response.internalError({ body: { message: err instanceof Error ? err.message : 'AI draft failed' } });
    }
  });

  // ── explain ──────────────────────────────────────────────────────────────────
  router.post({
    path: '/api/babel/ai/explain',
    options: { access: 'public' },
    security: { authz: { enabled: false, reason: 'AI explain; operates on rule YAML only' } },
    validate: { body: schema.object({ ruleYaml: schema.string() }) },
  }, async (ctx, request, response) => {
    const { ruleYaml } = request.body as any;
    const cfg = await readAiProviderConfig(ctx);

    if (cfg.provider === 'connector') {
      return proxyToConnector(ctx, request, response, { action: 'explain', rule_yaml: ruleYaml });
    }

    const llmHeaders = await buildLlmHeaders(ctx);
    try {
      const res = await proxyPost(`${SIGMA_API_URL}/ai/explain`, { rule_yaml: ruleYaml }, llmHeaders);
      const body = await res.json().catch(() => null);
      return res.ok ? response.ok({ body }) : response.customError({ statusCode: res.status, body: { message: body?.message ?? 'AI explain failed' } });
    } catch (err: unknown) {
      return response.internalError({ body: { message: err instanceof Error ? err.message : 'AI explain failed' } });
    }
  });

  // ── improve ──────────────────────────────────────────────────────────────────
  router.post({
    path: '/api/babel/ai/improve',
    options: { access: 'public' },
    security: { authz: { enabled: false, reason: 'AI improve; ES field context only' } },
    validate: {
      body: schema.object({
        ruleYaml:     schema.string(),
        indexPattern: schema.maybe(schema.string()),
      }),
    },
  }, async (ctx, request, response) => {
    const { ruleYaml, indexPattern } = request.body as any;
    const cfg = await readAiProviderConfig(ctx);

    if (cfg.provider === 'connector') {
      return proxyToConnector(ctx, request, response, {
        action: 'improve', rule_yaml: ruleYaml, index_pattern: indexPattern,
      });
    }

    const llmHeaders = await buildLlmHeaders(ctx);
    try {
      const res = await proxyPost(`${SIGMA_API_URL}/ai/improve`, {
        rule_yaml: ruleYaml, index_pattern: indexPattern ?? 'logs-*',
      }, llmHeaders);
      const body = await res.json().catch(() => null);
      return res.ok ? response.ok({ body }) : response.customError({ statusCode: res.status, body: { message: body?.message ?? 'AI improve failed' } });
    } catch (err: unknown) {
      return response.internalError({ body: { message: err instanceof Error ? err.message : 'AI improve failed' } });
    }
  });

  // ── draft-from-alert ─────────────────────────────────────────────────────────
  router.post({
    path: '/api/babel/ai/draft-from-alert',
    options: { access: 'public' },
    security: { authz: { enabled: false, reason: 'Alert data fetched via server-side credentials' } },
    validate: {
      body: schema.object({
        alertId: schema.string(),
        source:  schema.maybe(schema.string()),
      }),
    },
  }, async (ctx, request, response) => {
    const { alertId, source } = request.body as any;
    const cfg = await readAiProviderConfig(ctx);

    if (cfg.provider === 'connector') {
      return proxyToConnector(ctx, request, response, {
        action: 'draft-from-alert', alert_id: alertId, source: source ?? 'kibana',
      });
    }

    const llmHeaders = await buildLlmHeaders(ctx);
    try {
      const res = await proxyPost(`${SIGMA_API_URL}/ai/draft-from-alert`, {
        alert_id: alertId, source: source ?? 'kibana',
      }, llmHeaders);
      const body = await res.json().catch(() => null);
      return res.ok ? response.ok({ body }) : response.customError({ statusCode: res.status, body: { message: body?.message ?? 'Alert draft failed' } });
    } catch (err: unknown) {
      return response.internalError({ body: { message: err instanceof Error ? err.message : 'Alert draft failed' } });
    }
  });

  // ── chat ─────────────────────────────────────────────────────────────────────
  router.post({
    path: '/api/babel/ai/chat',
    options: { access: 'public' },
    security: { authz: { enabled: false, reason: 'Chat context is rule YAML only; no ES data' } },
    validate: {
      body: schema.object({
        messages:    schema.arrayOf(schema.object({ role: schema.string(), content: schema.string() })),
        ruleContext: schema.maybe(schema.string()),
      }),
    },
  }, async (ctx, request, response) => {
    const { messages, ruleContext } = request.body as any;
    const cfg = await readAiProviderConfig(ctx);

    if (cfg.provider === 'connector') {
      return proxyToConnector(ctx, request, response, {
        action: 'chat', messages, rule_yaml: ruleContext,
      });
    }

    const llmHeaders = await buildLlmHeaders(ctx);
    try {
      const res = await proxyPost(`${SIGMA_API_URL}/ai/chat`, {
        messages, rule_context: ruleContext ?? null,
      }, llmHeaders);
      const body = await res.json().catch(() => null);
      return res.ok
        ? response.ok({ body })
        : response.customError({ statusCode: res.status, body: { message: body?.message ?? 'Chat failed' } });
    } catch (err: unknown) {
      return response.internalError({ body: { message: err instanceof Error ? err.message : 'Chat failed' } });
    }
  });

  // ── list alerts ──────────────────────────────────────────────────────────────
  router.get({
    path: '/api/babel/ai/alerts',
    options: { access: 'public' },
    security: { authz: { enabled: false, reason: 'Alert listing uses server-side ES credentials' } },
    validate: {
      query: schema.object({
        source: schema.maybe(schema.string()),
        size:   schema.maybe(schema.number()),
      }),
    },
  }, async (_ctx, request, response) => {
    const { source, size } = request.query as any;
    const params = new URLSearchParams();
    if (source) params.set('source', source);
    if (size)   params.set('size', String(size));
    try {
      const res = await fetch(`${SIGMA_API_URL}/ai/alerts?${params}`, {
        headers: { ...sigmaAuthHeader() },
      });
      const body = await res.json().catch(() => null);
      return res.ok ? response.ok({ body }) : response.customError({ statusCode: res.status, body: { message: body?.detail ?? 'Alert list failed' } });
    } catch (err: unknown) {
      return response.internalError({ body: { message: err instanceof Error ? err.message : 'Alert list failed' } });
    }
  });
}

// ── Helper: proxy an AI action through the Kibana connector route ─────────────
async function proxyToConnector(
  ctx: any,
  request: any,
  response: any,
  actionBody: Record<string, unknown>,
) {
  const KIBANA_URL = process.env.KIBANA_URL || 'http://localhost:5601';
  const fwdHeaders: Record<string, string> = { 'content-type': 'application/json', 'kbn-xsrf': 'sigma-ui' };
  if (request.headers.cookie)        fwdHeaders['cookie']        = request.headers.cookie as string;
  if (request.headers.authorization) fwdHeaders['authorization'] = request.headers.authorization as string;

  try {
    const res = await fetch(`${KIBANA_URL}/api/babel/ai/invoke-connector`, {
      method: 'POST',
      headers: fwdHeaders,
      body: JSON.stringify(actionBody),
    });
    const body = await res.json().catch(() => null);
    return res.ok
      ? response.ok({ body })
      : response.customError({ statusCode: res.status, body: { message: body?.message ?? 'Connector invocation failed' } });
  } catch (err: unknown) {
    return response.internalError({ body: { message: err instanceof Error ? err.message : 'Connector invocation failed' } });
  }
}
