/**
 * Búsqueda de solo lectura en el tráfico de Cloudflare (`b89-cloudflare-traffic-*`) a través del
 * gateway del Indexer (`POST /wazuh/traffic/_search`, mismo token que la ingesta). La consultan
 * Bunny y el MCP con una query construida en el servidor; nunca DSL del usuario.
 */

export type CloudflareTrafficSearch = (
  body: Readonly<Record<string, unknown>>,
  signal?: AbortSignal,
) => Promise<unknown>;

export class CloudflareTrafficError extends Error {
  public constructor(public readonly code: 'TRAFFIC_UNAVAILABLE' | 'TRAFFIC_FORBIDDEN') {
    super(code);
    this.name = 'CloudflareTrafficError';
  }
}

const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

export function createCloudflareTrafficSearch(options: {
  readonly gatewayBaseUrl: string;
  readonly accessToken: () => Promise<string>;
  readonly fetch?: typeof fetch;
}): CloudflareTrafficSearch {
  const base = options.gatewayBaseUrl.replace(/\/+$/u, '');
  const doFetch = options.fetch ?? fetch;
  return async (body, signal) => {
    const timeout = AbortSignal.timeout(15_000);
    const combined = signal ? AbortSignal.any([signal, timeout]) : timeout;
    let response: Response;
    try {
      response = await doFetch(`${base}/wazuh/traffic/_search`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${await options.accessToken()}`,
          'content-type': 'application/json',
          accept: 'application/json',
        },
        body: JSON.stringify(body),
        redirect: 'error',
        signal: combined,
      });
    } catch {
      throw new CloudflareTrafficError('TRAFFIC_UNAVAILABLE');
    }
    if (response.status === 401 || response.status === 403) {
      throw new CloudflareTrafficError('TRAFFIC_FORBIDDEN');
    }
    const text = await response.text();
    if (response.status !== 200 || text.length > MAX_RESPONSE_BYTES) {
      throw new CloudflareTrafficError('TRAFFIC_UNAVAILABLE');
    }
    try {
      return JSON.parse(text) as unknown;
    } catch {
      throw new CloudflareTrafficError('TRAFFIC_UNAVAILABLE');
    }
  };
}
