import { IRouter } from '@kbn/core/server';
import { schema } from '@kbn/config-schema';
import { PluginConfig } from '../config';

const SIGMA_API_KEY = process.env.SIGMA_API_KEY || '';

function authHeader(): Record<string, string> {
  return SIGMA_API_KEY ? { authorization: `Bearer ${SIGMA_API_KEY}` } : {};
}

export function registerSigmaSchemaDriftRoutes(router: IRouter, config: PluginConfig): void {
  const SIGMA_API_URL = config.sigmaApiUrl;
  // POST /api/babel/schema-drift/snapshot
  router.post(
    {
      path: '/api/babel/schema-drift/snapshot',
      options: { access: 'public' },
      security: { authz: { enabled: false, reason: 'Schema snapshot reads index mappings, no document data' } },
      validate: {
        body: schema.object({ indexPattern: schema.string() }),
      },
    },
    async (_ctx, request, response) => {
      const { indexPattern } = request.body as { indexPattern: string };
      try {
        const res = await fetch(`${SIGMA_API_URL}/schema-drift/snapshot`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', ...authHeader() },
          body: JSON.stringify({ index_pattern: indexPattern }),
        });
        const body = await res.json().catch(() => null);
        return res.ok ? response.ok({ body }) : response.customError({ statusCode: res.status, body: { message: body?.detail ?? 'Snapshot failed' } });
      } catch (err: unknown) {
        return response.internalError({ body: { message: err instanceof Error ? err.message : 'Snapshot failed' } });
      }
    }
  );

  // POST /api/babel/schema-drift/snapshot/so — Security Onion patterns
  router.post(
    {
      path: '/api/babel/schema-drift/snapshot/so',
      options: { access: 'public' },
      security: { authz: { enabled: false, reason: 'Snapshots SO index mappings, no document data' } },
      validate: false,
    },
    async (_ctx, _request, response) => {
      try {
        const res = await fetch(`${SIGMA_API_URL}/schema-drift/snapshot/so`, {
          method: 'POST',
          headers: { ...authHeader() },
        });
        const body = await res.json().catch(() => null);
        return res.ok ? response.ok({ body }) : response.customError({ statusCode: res.status, body: { message: body?.detail ?? 'SO snapshot failed' } });
      } catch (err: unknown) {
        return response.internalError({ body: { message: err instanceof Error ? err.message : 'SO snapshot failed' } });
      }
    }
  );

  // GET /api/babel/schema-drift/report?indexPattern=...
  router.get(
    {
      path: '/api/babel/schema-drift/report',
      options: { access: 'public' },
      security: { authz: { enabled: false, reason: 'Drift report reads mapping metadata only' } },
      validate: {
        query: schema.object({ indexPattern: schema.string() }),
      },
    },
    async (_ctx, request, response) => {
      const { indexPattern } = request.query as { indexPattern: string };
      try {
        const res = await fetch(
          `${SIGMA_API_URL}/schema-drift/report?index_pattern=${encodeURIComponent(indexPattern)}`,
          { headers: { ...authHeader() } }
        );
        const body = await res.json().catch(() => null);
        return res.ok ? response.ok({ body }) : response.customError({ statusCode: res.status, body: { message: body?.detail ?? 'Drift report failed' } });
      } catch (err: unknown) {
        return response.internalError({ body: { message: err instanceof Error ? err.message : 'Drift report failed' } });
      }
    }
  );
}
