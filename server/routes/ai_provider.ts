import { IRouter } from '@kbn/core/server';
import { schema } from '@kbn/config-schema';

const CONFIG_INDEX = 'sui_config';
const PROVIDER_DOC_ID = 'ai_provider';

// Default provider used when nothing has been saved yet: a local Gemma-4 12B coder
// GGUF served by Ollama. Pull it first with:
//   ollama pull hf.co/yuxinlu1/gemma-4-12B-coder-fable5-composer2.5-v1-GGUF:Q4_K_M
// Override any of this in Settings → Integration & Status → AI Provider.
const DEFAULT_AI_PROVIDER: AiProviderConfig = {
  provider: 'ollama',
  model: 'hf.co/yuxinlu1/gemma-4-12B-coder-fable5-composer2.5-v1-GGUF:Q4_K_M',
  base_url: 'http://host.docker.internal:11434/v1',
};

// LLM connector type IDs registered in Kibana Stack Management
const LLM_CONNECTOR_TYPES = new Set(['.gen-ai', '.bedrock', '.gemini', '.inference', '.d3security']);

export interface AiProviderConfig {
  provider: 'anthropic' | 'openai' | 'openai_compat' | 'ollama' | 'connector';
  model?: string;
  base_url?: string;
  api_key?: string;        // stored; masked on read
  connector_id?: string;
  connector_type?: string;
  connector_name?: string;
}

function maskKey(k: string): string {
  if (!k || k.length <= 8) return '****';
  return `${k.slice(0, 4)}****${k.slice(-4)}`;
}

/** Read the full (unmasked) provider config from ES. Used internally by sigma_ai.ts. */
export async function readAiProviderConfig(context: any): Promise<AiProviderConfig> {
  try {
    const { elasticsearch } = await context.core;
    const client = elasticsearch.client.asCurrentUser;
    const doc = await (client as any).get({ index: CONFIG_INDEX, id: PROVIDER_DOC_ID });
    return (doc._source as unknown as AiProviderConfig) ?? DEFAULT_AI_PROVIDER;
  } catch {
    return DEFAULT_AI_PROVIDER;
  }
}

/** Build the provider headers to forward to sigma-api for non-connector modes. */
export function providerHeaders(cfg: AiProviderConfig, anthropicKey: string): Record<string, string> {
  const h: Record<string, string> = {};
  h['x-llm-provider'] = cfg.provider;
  if (cfg.model) h['x-llm-model'] = cfg.model;
  if (cfg.base_url) h['x-llm-base-url'] = cfg.base_url;

  if (cfg.provider === 'anthropic') {
    if (anthropicKey) h['x-anthropic-api-key'] = anthropicKey;
  } else if (cfg.api_key) {
    h['x-llm-api-key'] = cfg.api_key;
  }
  return h;
}

/** Call a Kibana connector and return the response text.
 *  Pass `messages` for multi-turn chat; otherwise a single user/system turn is built. */
async function executeConnector(
  connectorId: string,
  connectorType: string,
  systemPrompt: string,
  userMessage: string,
  kibanaHeaders: Record<string, string>,
  messages?: Array<{ role: string; content: string }>,
): Promise<string> {
  const KIBANA_URL = process.env.KIBANA_URL || 'http://localhost:5601';

  // Build the message list for multi-turn vs single-turn
  const turnMessages = messages ?? [{ role: 'user', content: userMessage }];

  let execBody: unknown;
  if (connectorType === '.inference') {
    execBody = {
      params: {
        subAction: 'unified_query',
        subActionParams: {
          body: {
            messages: [
              { role: 'system', content: systemPrompt },
              ...turnMessages,
            ],
          },
        },
      },
    };
  } else {
    // .gen-ai (OpenAI), .bedrock, .gemini — invokeAI supports messages + system
    execBody = {
      params: {
        subAction: 'invokeAI',
        subActionParams: {
          messages: turnMessages,
          system: systemPrompt,
        },
      },
    };
  }

  const res = await fetch(
    `${KIBANA_URL}/api/actions/connector/${encodeURIComponent(connectorId)}/_execute`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'kbn-xsrf': 'sigma-ui',
        ...kibanaHeaders,
      },
      body: JSON.stringify(execBody),
    },
  );

  if (!res.ok) {
    const err = await res.json().catch(() => null);
    throw new Error(err?.message ?? `Connector execute failed with status ${res.status}`);
  }

  const result: any = await res.json();
  if (result.status !== 'ok') throw new Error(result.message ?? 'Connector returned non-OK status');
  // All LLM connectors normalise their response to data.message
  return result.data?.message ?? result.data?.completion ?? JSON.stringify(result.data);
}

// ── Prompt templates used by Kibana-side connector invocations ────────────────

const SIGMA_EXPERT_SYSTEM = `You are a senior detection engineer specialising in SIGMA rules, \
the Elastic Common Schema (ECS), and MITRE ATT&CK.

STRICT OUTPUT RULES — violating any will break the parser:
1. Output ONLY valid SIGMA YAML. No markdown fences, no prose before or after.
2. Do NOT include an id: field. If you must, it MUST be a lowercase UUID4 \
(e.g. a1b2c3d4-e5f6-4789-a0b1-c2d3e4f5a6b7). A descriptive name is INVALID. Safest: omit id entirely.
3. The detection: block MUST have at least one named selection with real non-empty field values and a condition: line.
4. Every field value in detection must be a non-empty string, integer, or list of non-empty strings.

Required fields: title, status (experimental), description, logsource, detection, level, falsepositives.`;

const EXPLAIN_SYSTEM = `You are a detection engineering educator. Given a SIGMA rule, produce:
**What it detects:** one paragraph
**Log sources monitored:** bullet list
**Detection logic:** step-by-step walkthrough
**MITRE ATT&CK:** technique IDs and tactic names
**Potential false positives:** bullet list
**Tuning suggestions:** 1-3 specific suggestions`;

const IMPROVE_SYSTEM = SIGMA_EXPERT_SYSTEM + `\n\nReturn:
1. An improved SIGMA YAML rule
2. A CHANGES section (bullet list) explaining what changed and why
Separate them with the literal line: ---CHANGES---`;

function buildIocPrompt(iocs: string[], context: any, logsourceHint?: string): string {
  const hint = logsourceHint ? `\nPreferred logsource category: ${logsourceHint}` : '';
  const fields = JSON.stringify(context?.field_mappings ?? {}, null, 2).slice(0, 3000);
  const events = JSON.stringify((context?.sample_events ?? []).slice(0, 2), null, 2).slice(0, 2000);
  return `Generate a SIGMA detection rule for the following IOCs:${hint}\n\nIOCs:\n${iocs.map(i => `- ${i}`).join('\n')}\n\nAvailable ECS fields:\n${fields}\n\nSample events:\n${events}`;
}

function buildImprovePrompt(ruleYaml: string, context: any): string {
  const fields = JSON.stringify(context?.field_mappings ?? {}, null, 2).slice(0, 3000);
  return `Review and improve this SIGMA rule.\n\nCurrent rule:\n${ruleYaml}\n\nAvailable ECS fields:\n${fields}`;
}

function buildAlertPrompt(alertDoc: any, fieldMappings: any): string {
  const alert = JSON.stringify(alertDoc, null, 2).slice(0, 3000);
  const fields = JSON.stringify(fieldMappings ?? {}, null, 2).slice(0, 2000);
  return `Convert this Kibana security alert to a SIGMA rule:\n\nAlert:\n${alert}\n\nAvailable ECS fields:\n${fields}`;
}

// ── Route registrations ───────────────────────────────────────────────────────

export function registerAiProviderRoutes(router: IRouter, sigmaApiUrl: string): void {

  // GET provider config (masked api_key)
  router.get({
    path: '/api/babel/ai/provider',
    options: { access: 'public' },
    security: { authz: { enabled: false, reason: 'AI provider config in sui_config index' } },
    validate: false,
  }, async (context, _req, response) => {
    const cfg = await readAiProviderConfig(context);
    const masked = { ...cfg, api_key: cfg.api_key ? maskKey(cfg.api_key) : undefined };
    return response.ok({ body: { success: true, data: masked } });
  });

  // POST provider config (save)
  router.post({
    path: '/api/babel/ai/provider',
    options: { access: 'public' },
    security: { authz: { enabled: false, reason: 'AI provider config in sui_config index' } },
    validate: {
      body: schema.object({
        provider:       schema.string(),
        model:          schema.maybe(schema.string()),
        base_url:       schema.maybe(schema.string()),
        api_key:        schema.maybe(schema.string()),
        connector_id:   schema.maybe(schema.string()),
        connector_type: schema.maybe(schema.string()),
        connector_name: schema.maybe(schema.string()),
      }),
    },
  }, async (context, request, response) => {
    const { elasticsearch } = await context.core;
    const client = elasticsearch.client.asCurrentUser;
    try {
      const incoming = request.body as unknown as AiProviderConfig;
      // If api_key is a masked value (contains ****), preserve the existing key
      if (incoming.api_key && incoming.api_key.includes('****')) {
        const existing = await readAiProviderConfig(context);
        incoming.api_key = existing.api_key;
      }
      await client.index({ index: CONFIG_INDEX, id: PROVIDER_DOC_ID, document: incoming });
      return response.ok({ body: { success: true } });
    } catch (err: unknown) {
      return response.internalError({ body: { message: 'Failed to save AI provider config' } });
    }
  });

  // GET available LLM connectors (from Kibana saved objects)
  router.get({
    path: '/api/babel/connectors',
    options: { access: 'public' },
    security: { authz: { enabled: false, reason: 'Lists connector metadata only' } },
    validate: false,
  }, async (context, _req, response) => {
    try {
      const { savedObjects } = await context.core;
      const result = await (savedObjects.client as any).find({
        type: 'action',
        perPage: 200,
        sortField: 'name',
        sortOrder: 'asc',
      } as any);
      const connectors = result.saved_objects
        .filter((so: any) => LLM_CONNECTOR_TYPES.has(so.attributes?.actionTypeId))
        .map((so: any) => ({
          id: so.id,
          name: so.attributes?.name ?? so.id,
          connector_type_id: so.attributes?.actionTypeId,
        }));
      return response.ok({ body: { connectors } });
    } catch (err: unknown) {
      return response.internalError({ body: { message: err instanceof Error ? err.message : 'Failed to list connectors' } });
    }
  });

  // POST invoke-connector — Kibana-side LLM call for connector mode
  // Handles the full AI action: gathers context from sigma-api, builds prompt, executes connector
  router.post({
    path: '/api/babel/ai/invoke-connector',
    options: { access: 'public' },
    security: { authz: { enabled: false, reason: 'Connector execution uses Kibana action framework' } },
    validate: {
      body: schema.object({
        action:         schema.string(),
        rule_yaml:      schema.maybe(schema.string()),
        iocs:           schema.maybe(schema.arrayOf(schema.string())),
        index_pattern:  schema.maybe(schema.string()),
        logsource_hint: schema.maybe(schema.string()),
        alert_id:       schema.maybe(schema.string()),
        source:         schema.maybe(schema.string()),
        messages:       schema.maybe(schema.arrayOf(schema.object({
          role:    schema.string(),
          content: schema.string(),
        }))),
      }),
    },
  }, async (context, request, response) => {
    const cfg = await readAiProviderConfig(context);
    const body = request.body as any;

    if (cfg.provider !== 'connector' || !cfg.connector_id) {
      return response.badRequest({ body: { message: 'Provider is not set to connector mode' } });
    }

    // Build auth headers to forward to both sigma-api and Kibana itself
    const fwdHeaders: Record<string, string> = {};
    if (request.headers.cookie)        fwdHeaders['cookie']        = request.headers.cookie as string;
    if (request.headers.authorization) fwdHeaders['authorization'] = request.headers.authorization as string;

    const sigmaApiKey = process.env.SIGMA_API_KEY || '';
    const sigmaHeaders: Record<string, string> = { 'content-type': 'application/json' };
    if (sigmaApiKey) sigmaHeaders['authorization'] = `Bearer ${sigmaApiKey}`;

    try {
      let systemPrompt: string;
      let userMessage: string;
      let resultKey: 'rule_yaml' | 'explanation' = 'rule_yaml';

      if (body.action === 'explain') {
        systemPrompt = EXPLAIN_SYSTEM;
        userMessage  = `Explain this SIGMA rule:\n\n${body.rule_yaml}`;
        resultKey    = 'explanation';

      } else if (body.action === 'improve') {
        // Gather field context from sigma-api
        const ctxRes = await fetch(`${sigmaApiUrl}/ai/gather-context`, {
          method: 'POST',
          headers: sigmaHeaders,
          body: JSON.stringify({ type: 'ioc', index_pattern: body.index_pattern ?? 'logs-*' }),
        });
        const ctx = ctxRes.ok ? (await ctxRes.json()).context : {};
        systemPrompt = IMPROVE_SYSTEM;
        userMessage  = buildImprovePrompt(body.rule_yaml, ctx);

      } else if (body.action === 'draft-from-iocs') {
        const ctxRes = await fetch(`${sigmaApiUrl}/ai/gather-context`, {
          method: 'POST',
          headers: sigmaHeaders,
          body: JSON.stringify({ type: 'ioc', index_pattern: body.index_pattern ?? 'logs-*' }),
        });
        const ctx = ctxRes.ok ? (await ctxRes.json()).context : {};
        systemPrompt = SIGMA_EXPERT_SYSTEM;
        userMessage  = buildIocPrompt(body.iocs ?? [], ctx, body.logsource_hint);

      } else if (body.action === 'draft-from-alert') {
        const ctxRes = await fetch(`${sigmaApiUrl}/ai/gather-context`, {
          method: 'POST',
          headers: sigmaHeaders,
          body: JSON.stringify({ type: 'alert', alert_id: body.alert_id, source: body.source ?? 'kibana' }),
        });
        const ctx = ctxRes.ok ? (await ctxRes.json()).context : {};
        systemPrompt = SIGMA_EXPERT_SYSTEM;
        userMessage  = buildAlertPrompt(ctx.alert_doc, ctx.field_mappings);

      } else if (body.action === 'chat') {
        const ruleCtx = body.rule_yaml
          ? `\n\nThe user currently has this SIGMA rule open in their editor:\n\`\`\`yaml\n${body.rule_yaml}\n\`\`\``
          : '';
        systemPrompt = `You are a senior detection engineer and SOC analyst with deep expertise in SIGMA rules, ECS, and MITRE ATT&CK.

When generating SIGMA rules output them in a \`\`\`yaml block and follow these rules:
DETECTION SYNTAX — use ONLY these forms:
  fieldname: value
  fieldname|contains: substring
  fieldname|startswith: prefix
  fieldname|endswith: suffix
  fieldname|gte: 1024
  fieldname: [value1, value2]

NEVER use ==, !=, >=, <=, >, < operators (those are EQL/KQL, not SIGMA).
NEVER use list items (- value) directly under a selection.
Use real ECS fields only. Omit id: field. status: experimental.
Every field value must be non-empty.${ruleCtx}`;
        const text = await executeConnector(
          cfg.connector_id!,
          cfg.connector_type ?? '.gen-ai',
          systemPrompt,
          '',
          fwdHeaders,
          body.messages as Array<{ role: string; content: string }>,
        );
        return response.ok({ body: { success: true, reply: text.trim() } });

      } else {
        return response.badRequest({ body: { message: `Unknown action: ${body.action}` } });
      }

      const text = await executeConnector(
        cfg.connector_id!,
        cfg.connector_type ?? '.gen-ai',
        systemPrompt,
        userMessage,
        fwdHeaders,
      );

      // Parse improve response — handles '---CHANGES---' literal and '---\nCHANGES:' variant
      if (body.action === 'improve') {
        let yamlPart = text;
        let changesPart = '';
        if (text.includes('---CHANGES---')) {
          [yamlPart, changesPart] = text.split('---CHANGES---', 2);
        } else {
          const m = text.match(/\n(---+)\s*\n+CHANGES[:\s]/i);
          if (m && m.index !== undefined) {
            yamlPart    = text.slice(0, m.index);
            changesPart = text.slice(m.index + m[0].length).trim();
          }
        }
        if (yamlPart !== text || changesPart) {
          return response.ok({ body: { success: true, rule_yaml: yamlPart.trim(), changes: changesPart.trim() } });
        }
      }

      return response.ok({ body: { success: true, [resultKey]: text.trim() } });

    } catch (err: unknown) {
      return response.internalError({ body: { message: err instanceof Error ? err.message : 'Connector invocation failed' } });
    }
  });
}
