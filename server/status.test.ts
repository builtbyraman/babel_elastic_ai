import { registerStatusRoute } from './routes/status';

describe('Status route', () => {
  it('registers a GET handler and returns consolidated status', async () => {
    let registeredHandler: any = null;

    const router: any = {
      get: (_config: any, handler: any) => { registeredHandler = handler; },
    };

    registerStatusRoute(router as any, { sigmaApiUrl: 'http://localhost:8000/v1' });
    expect(typeof registeredHandler).toBe('function');

    // Mock fetch for external API
    (global as any).fetch = jest.fn().mockResolvedValue({ ok: true, json: async () => ({ status: 'healthy' }) });

    const fakeContext: any = {
      core: {
        elasticsearch: {
          client: {
            asCurrentUser: {
              cluster: { health: async () => ({ status: 'green' }) },
              info: async () => ({ version: { number: '8.10.0' } }),
            },
          },
        },
      },
    };

    const fakeRequest: any = { headers: { authorization: 'Bearer abc' } };

    const response: any = {
      ok: ({ body }: any) => ({ statusCode: 200, body }),
      internalError: ({ body }: any) => ({ statusCode: 500, body }),
    };

    const result = await registeredHandler(fakeContext, fakeRequest, response as any);
    expect(result.statusCode).toBe(200);
    expect(result.body).toHaveProperty('services');
    expect(Array.isArray(result.body.services)).toBe(true);
    expect(result.body.services.some((s: any) => s.name === 'Sigma Conversion API')).toBe(true);
    expect(result.body.services.some((s: any) => s.name === 'Elasticsearch')).toBe(true);
  });
});
