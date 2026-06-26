import { IRouter } from '@kbn/core/server';
import { schema } from '@kbn/config-schema';

const CONFIG_INDEX = 'sui_config';
const ANTHROPIC_KEY_DOC_ID = 'anthropic_key';

function maskKey(key: string): string {
  if (key.length <= 8) return '****';
  return `${key.slice(0, 7)}****${key.slice(-4)}`;
}

export function registerAnthropicKeyRoutes(router: IRouter): void {
  router.get(
    {
      path: '/api/babel/anthropic-key',
      options: { access: 'public' },
      security: { authz: { enabled: false, reason: 'Stored in Elasticsearch via asCurrentUser' } },
      validate: false,
    },
    async (context, _request, response) => {
      const { elasticsearch } = await context.core;
      const client = elasticsearch.client.asCurrentUser;
      try {
        const doc = await (client as any).get({ index: CONFIG_INDEX, id: ANTHROPIC_KEY_DOC_ID });
        const key: string = doc._source?.value ?? '';
        return response.ok({ body: { success: true, data: { masked: maskKey(key), configured: key.length > 0 } } });
      } catch (err: any) {
        if (err?.statusCode === 404 || err?.meta?.statusCode === 404) {
          return response.ok({ body: { success: true, data: { masked: '', configured: false } } });
        }
        return response.internalError({ body: { message: 'Failed to retrieve Anthropic key' } });
      }
    }
  );

  router.post(
    {
      path: '/api/babel/anthropic-key',
      options: { access: 'public' },
      security: { authz: { enabled: false, reason: 'Stored in Elasticsearch via asCurrentUser' } },
      validate: { body: schema.object({ apiKey: schema.string() }) },
    },
    async (context, request, response) => {
      const { apiKey } = request.body as { apiKey: string };
      const { elasticsearch } = await context.core;
      const client = elasticsearch.client.asCurrentUser;
      try {
        await client.index({ index: CONFIG_INDEX, id: ANTHROPIC_KEY_DOC_ID, document: { value: apiKey } });
        return response.ok({ body: { success: true } });
      } catch (err: unknown) {
        return response.internalError({ body: { message: 'Failed to save Anthropic key' } });
      }
    }
  );

  // Internal helper used by AI routes to read the raw key for forwarding
  router.get(
    {
      path: '/api/babel/anthropic-key/raw',
      options: { access: 'public' },
      security: { authz: { enabled: false, reason: 'Server-side use only; forwards key to sigma-api' } },
      validate: false,
    },
    async (context, _request, response) => {
      const { elasticsearch } = await context.core;
      const client = elasticsearch.client.asCurrentUser;
      try {
        const doc = await (client as any).get({ index: CONFIG_INDEX, id: ANTHROPIC_KEY_DOC_ID });
        const key: string = doc._source?.value ?? '';
        return response.ok({ body: { key } });
      } catch (err: any) {
        if (err?.statusCode === 404 || err?.meta?.statusCode === 404) {
          return response.ok({ body: { key: '' } });
        }
        return response.internalError({ body: { message: 'Failed to retrieve Anthropic key' } });
      }
    }
  );
}

// Helper used by sigma_ai.ts to read the Anthropic key from ES
export async function readAnthropicKey(context: any): Promise<string> {
  try {
    const { elasticsearch } = await context.core;
    const client = elasticsearch.client.asCurrentUser;
    const doc = await (client as any).get({ index: CONFIG_INDEX, id: ANTHROPIC_KEY_DOC_ID });
    return (doc._source?.value as string) ?? '';
  } catch {
    return '';
  }
}
