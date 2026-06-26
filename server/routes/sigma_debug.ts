import { IRouter } from '@kbn/core/server';

const SIGMA_INDEX = 'sui_sigma_doc';

export function registerSigmaDebugRoute(router: IRouter): void {
  router.get(
    {
      path: '/api/babel/debug-index',
      options: { access: 'public' },
      security: { authz: { enabled: false, reason: 'Debug endpoint' } },
      validate: false,
    },
    async (context, _request, response) => {
      const { elasticsearch } = await context.core;
      const client = elasticsearch.client.asCurrentUser;

      try {
        // Count all docs
        const countRes = await (client as any).count({ index: SIGMA_INDEX });

        // Get mapping
        const mappingRes = await (client as any).indices.getMapping({ index: SIGMA_INDEX });

        // Get a sample doc to inspect structure
        const sampleRes = await (client as any).search({
          index: SIGMA_INDEX,
          size: 1,
          body: { query: { match_all: {} } },
        });

        // Check for docs without a title (common source of issues)
        const noTitleRes = await (client as any).count({
          index: SIGMA_INDEX,
          body: { query: { bool: { must_not: { exists: { field: 'title' } } } } },
        });

        const mapping = mappingRes[SIGMA_INDEX]?.mappings ?? mappingRes;
        const sampleDoc = sampleRes.hits?.hits?.[0]?._source ?? null;

        return response.ok({
          body: {
            total_docs: countRes.count,
            docs_without_title: noTitleRes.count,
            detection_mapping: (mapping as any)?.properties?.detection,
            tags_mapping: (mapping as any)?.properties?.tags,
            title_mapping: (mapping as any)?.properties?.title,
            sample_doc_keys: sampleDoc ? Object.keys(sampleDoc) : [],
          },
        });
      } catch (err: unknown) {
        return response.internalError({
          body: { message: err instanceof Error ? err.message : 'Debug failed' },
        });
      }
    }
  );
}
