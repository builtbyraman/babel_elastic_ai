import { IRouter } from '@kbn/core/server';
import { schema } from '@kbn/config-schema';
import { PluginConfig } from '../config';

const SIGMA_API_KEY = process.env.SIGMA_API_KEY || '';

function authHeader(): Record<string, string> {
  return SIGMA_API_KEY ? { authorization: `Bearer ${SIGMA_API_KEY}` } : {};
}

export function registerSigmaRuleRegistryRoutes(router: IRouter, config: PluginConfig): void {
  const SIGMA_API_URL = config.sigmaApiUrl;
  // POST /api/babel/rules/register — called automatically by deploy route
  router.post(
    {
      path: '/api/babel/rules/register',
      options: { access: 'public' },
      security: { authz: { enabled: false, reason: 'Registry stores rule metadata, no privileged data access' } },
      validate: {
        body: schema.object({
          kibanaRuleId: schema.string(),
          ruleYaml: schema.string(),
          title: schema.string(),
        }),
      },
    },
    async (_ctx, request, response) => {
      const { kibanaRuleId, ruleYaml, title } = request.body as {
        kibanaRuleId: string;
        ruleYaml: string;
        title: string;
      };
      try {
        const res = await fetch(`${SIGMA_API_URL}/rules/register`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', ...authHeader() },
          body: JSON.stringify({ kibana_rule_id: kibanaRuleId, rule_yaml: ruleYaml, title }),
        });
        const body = await res.json().catch(() => null);
        return res.ok ? response.ok({ body }) : response.customError({ statusCode: res.status, body: { message: body?.detail ?? 'Registration failed' } });
      } catch (err: unknown) {
        return response.internalError({ body: { message: err instanceof Error ? err.message : 'Registration failed' } });
      }
    }
  );

  // GET /api/babel/rules/source?kibanaRuleId=...
  router.get(
    {
      path: '/api/babel/rules/source',
      options: { access: 'public' },
      security: { authz: { enabled: false, reason: 'Returns sigma YAML stored at deploy time' } },
      validate: {
        query: schema.object({ kibanaRuleId: schema.string() }),
      },
    },
    async (_ctx, request, response) => {
      const { kibanaRuleId } = request.query as { kibanaRuleId: string };
      try {
        const res = await fetch(
          `${SIGMA_API_URL}/rules/source?kibana_rule_id=${encodeURIComponent(kibanaRuleId)}`,
          { headers: { ...authHeader() } }
        );
        const body = await res.json().catch(() => null);
        if (res.status === 404) {
          return response.notFound({ body: { message: body?.detail ?? 'Rule source not found' } });
        }
        return res.ok ? response.ok({ body }) : response.customError({ statusCode: res.status, body: { message: body?.detail ?? 'Source fetch failed' } });
      } catch (err: unknown) {
        return response.internalError({ body: { message: err instanceof Error ? err.message : 'Source fetch failed' } });
      }
    }
  );
}
