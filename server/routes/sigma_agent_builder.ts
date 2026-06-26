import { IRouter } from '@kbn/core/server';

const KIBANA_URL = process.env.KIBANA_URL || 'http://localhost:5601';

// Agent definitions using the exact Agent Builder API format from the notebook.
// These create persistent Kibana chat agents with scoped ES tool access.
const SIGMA_AI_AGENTS = [
  {
    id: 'sigma-ai-ioc-drafter',
    name: 'SIGMA IOC Rule Drafter',
    description: 'Drafts SIGMA detection rules from Indicators of Compromise using live ES field context.',
    avatar_color: '#D3DAE6',
    avatar_symbol: 'SR',
    configuration: {
      instructions: `You are a senior detection engineer. When given a list of IOCs (IPs, hashes, process names, registry keys, domains, file paths), do the following:
1. Call get_index_mapping on the relevant index pattern to understand available ECS fields
2. Call search to find events matching the IOCs and understand their structure
3. Generate a well-formed SIGMA rule YAML that detects the IOC pattern

Always output valid SIGMA YAML with: title, status, description, logsource, detection (named selections + condition), level, tags (ATT&CK), falsepositives.`,
      tools: [{
        tool_ids: [
          'platform.core.search',
          'platform.core.get_index_mapping',
          'platform.core.list_indices',
          'platform.core.execute_esql',
        ],
      }],
    },
  },
  {
    id: 'sigma-ai-alert-converter',
    name: 'SIGMA Alert Converter',
    description: 'Converts Kibana security alerts or Security Onion alerts into portable SIGMA rules.',
    avatar_color: '#F5A700',
    avatar_symbol: 'AC',
    configuration: {
      instructions: `You are a senior detection engineer specialising in alert triage and rule portability. When given an alert ID or alert content:
1. Call get_document_by_id to fetch the full alert document
2. Call get_index_mapping to understand the schema of the alert index
3. Extract behavioural indicators: process names, file paths, registry keys, network destinations, command lines
4. Generate a SIGMA rule that detects the same behaviour — not just the specific IOC values, but the behavioural pattern

For Security Onion Suricata alerts: translate to a host-level SIGMA rule, not a network signature.
Output valid SIGMA YAML only.`,
      tools: [{
        tool_ids: [
          'platform.core.search',
          'platform.core.get_index_mapping',
          'platform.core.get_document_by_id',
          'platform.core.execute_esql',
        ],
      }],
    },
  },
  {
    id: 'sigma-ai-rule-advisor',
    name: 'SIGMA Rule Advisor',
    description: 'Explains and improves SIGMA rules using live field context from your Elasticsearch environment.',
    avatar_color: '#00BFB3',
    avatar_symbol: 'RA',
    configuration: {
      instructions: `You are a detection engineering educator and SIGMA expert. You help analysts understand and improve their detection rules.

When asked to EXPLAIN a rule: describe what it detects, the log sources, the detection logic step by step, MITRE ATT&CK relevance, and false positive scenarios.

When asked to IMPROVE a rule:
1. Call get_index_mapping on the rule's logsource index pattern to verify field availability
2. Suggest improvements for: false positive reduction, field mapping accuracy, ATT&CK coverage, condition logic clarity
3. Return the improved rule YAML followed by a bullet list of changes

Always be specific and actionable.`,
      tools: [{
        tool_ids: [
          'platform.core.search',
          'platform.core.get_index_mapping',
          'platform.core.list_indices',
          'platform.core.generate_esql',
        ],
      }],
    },
  },
];

export function registerSigmaAgentBuilderRoute(router: IRouter): void {
  router.post(
    {
      path: '/api/babel/agent-builder/setup',
      options: { access: 'public' },
      security: { authz: { enabled: false, reason: 'Agent Builder setup uses Kibana admin auth forwarded from request' } },
      validate: false,
    },
    async (_ctx, request, response) => {
      const cookieHeader = request.headers['cookie'];
      const userAuthHeader = request.headers['authorization'];

      const kibanaHeaders: Record<string, string> = {
        'Content-Type': 'application/json',
        'kbn-xsrf': 'true',
      };
      if (cookieHeader) {
        kibanaHeaders['cookie'] = Array.isArray(cookieHeader) ? cookieHeader.join('; ') : cookieHeader as string;
      }
      if (userAuthHeader) {
        kibanaHeaders['authorization'] = Array.isArray(userAuthHeader) ? userAuthHeader[0] : userAuthHeader as string;
      }

      const results: Array<{ id: string; status: string; message?: string }> = [];

      for (const agent of SIGMA_AI_AGENTS) {
        try {
          const res = await fetch(`${KIBANA_URL}/api/agent_builder/agents`, {
            method: 'POST',
            headers: kibanaHeaders,
            body: JSON.stringify(agent),
          });
          const payload = await res.json().catch(() => null);
          results.push({
            id: agent.id,
            status: res.ok ? 'created' : 'error',
            message: res.ok ? undefined : (payload?.message ?? `HTTP ${res.status}`),
          });
        } catch (err: unknown) {
          results.push({
            id: agent.id,
            status: 'error',
            message: err instanceof Error ? err.message : 'Unknown error',
          });
        }
      }

      const allOk = results.every(r => r.status === 'created');
      return response.ok({ body: { success: allOk, agents: results } });
    }
  );

  router.delete(
    {
      path: '/api/babel/agent-builder/teardown',
      options: { access: 'public' },
      security: { authz: { enabled: false, reason: 'Agent Builder teardown uses Kibana admin auth forwarded from request' } },
      validate: false,
    },
    async (_ctx, request, response) => {
      const cookieHeader = request.headers['cookie'];
      const userAuthHeader = request.headers['authorization'];
      const kibanaHeaders: Record<string, string> = { 'kbn-xsrf': 'true' };
      if (cookieHeader) kibanaHeaders['cookie'] = Array.isArray(cookieHeader) ? cookieHeader.join('; ') : cookieHeader as string;
      if (userAuthHeader) kibanaHeaders['authorization'] = Array.isArray(userAuthHeader) ? userAuthHeader[0] : userAuthHeader as string;

      const results: Array<{ id: string; status: string }> = [];
      for (const agent of SIGMA_AI_AGENTS) {
        try {
          const res = await fetch(`${KIBANA_URL}/api/agent_builder/agents/${agent.id}`, {
            method: 'DELETE',
            headers: kibanaHeaders,
          });
          results.push({ id: agent.id, status: res.ok ? 'deleted' : 'error' });
        } catch {
          results.push({ id: agent.id, status: 'error' });
        }
      }
      return response.ok({ body: { agents: results } });
    }
  );

  // Reports whether Elastic Agent Builder is available on this Kibana, and which of
  // Babel's SIGMA agents are currently registered. Degrades gracefully: a 403/404
  // from the Agent Builder API (feature gated / not present) returns available:false
  // rather than an error, so the UI can show a "not available" state.
  router.get(
    {
      path: '/api/babel/agent-builder/status',
      options: { access: 'public' },
      security: { authz: { enabled: false, reason: 'Agent Builder status uses Kibana auth forwarded from request' } },
      validate: false,
    },
    async (_ctx, request, response) => {
      const cookieHeader = request.headers['cookie'];
      const userAuthHeader = request.headers['authorization'];
      const kibanaHeaders: Record<string, string> = { 'kbn-xsrf': 'true' };
      if (cookieHeader) kibanaHeaders['cookie'] = Array.isArray(cookieHeader) ? cookieHeader.join('; ') : cookieHeader as string;
      if (userAuthHeader) kibanaHeaders['authorization'] = Array.isArray(userAuthHeader) ? userAuthHeader[0] : userAuthHeader as string;

      const ids = SIGMA_AI_AGENTS.map(a => ({ id: a.id, name: a.name }));
      try {
        const res = await fetch(`${KIBANA_URL}/api/agent_builder/agents`, { method: 'GET', headers: kibanaHeaders });
        if (!res.ok) {
          // Feature gated (403) or absent (404) — report unavailable with the upstream code.
          return response.ok({
            body: {
              available: false,
              reason: `Elastic Agent Builder API returned HTTP ${res.status}. It may be disabled or require a feature flag/license on this Kibana.`,
              agents: ids.map(a => ({ ...a, registered: false })),
            },
          });
        }
        const payload: any = await res.json().catch(() => null);
        // Agent Builder may return an array or { results: [...] } / { agents: [...] }.
        const list: any[] = Array.isArray(payload) ? payload : (payload?.results ?? payload?.agents ?? []);
        const existing = new Set(list.map((a: any) => a?.id).filter(Boolean));
        return response.ok({
          body: {
            available: true,
            agents: ids.map(a => ({ ...a, registered: existing.has(a.id) })),
          },
        });
      } catch (err: unknown) {
        return response.ok({
          body: {
            available: false,
            reason: err instanceof Error ? err.message : 'Could not reach the Elastic Agent Builder API',
            agents: ids.map(a => ({ ...a, registered: false })),
          },
        });
      }
    }
  );
}
