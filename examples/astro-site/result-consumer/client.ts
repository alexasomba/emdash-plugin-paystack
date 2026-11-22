import { canonicalAttestationFrame } from '../../../src/security/attestation.js';
import { encodeBase64Url, toHex } from '../../../src/security/encryption.js';
import { fromRawHostExecution } from '../../../src/routes/response.js';
import { isVerifiedPaymentResult, type VerifiedPaymentResult } from '../../../src/domain/result.js';
import { isPlainObject } from '../../../src/storage/schema.js';

interface ClientOptions {
  readonly installedPluginId: string;
  readonly siteId: string;
  readonly consumerId: string;
  readonly keyId: string;
  readonly key: Uint8Array;
  /** Persistent site-owned quota. Return false on denial or unavailable storage. */
  readonly consumeQuota: (kind: 'feed' | 'ack', consumerId: string) => Promise<boolean>;
  readonly invoke?: (pluginId: string, path: string, request: Request) => Promise<unknown>;
  readonly now?: () => number;
}
export type Feed = { readonly items: readonly VerifiedPaymentResult[]; readonly nextCursor?: string };
const identifier = /^[A-Za-z0-9_-]{1,120}$/u;
const eventId = /^psk:v1:results:[a-f0-9]{64}$/u;

/** Server-only fixed-route consumer. Call from an authenticated site job, never the browser. */
export function createResultClient(options: ClientOptions) {
  const configured = identifier.test(options.siteId) && identifier.test(options.consumerId) && identifier.test(options.keyId) &&
    typeof options.installedPluginId === 'string' && options.installedPluginId.length > 0 && options.installedPluginId.length <= 255 &&
    options.key instanceof Uint8Array && options.key.byteLength === 32 && typeof options.consumeQuota === 'function';
  const invoke = options.invoke ?? (async (id, path, request) => {
    const { withEmDashRuntime } = await import('emdash/middleware');
    return withEmDashRuntime((runtime) => runtime.handlePluginApiRoute(id, 'POST', `/${path}`, request));
  });
  async function call(route: 'results/feed' | 'results/ack', body: Record<string, unknown>): Promise<unknown> {
    if (!configured) return null;
    try {
      if (!await options.consumeQuota(route === 'results/feed' ? 'feed' : 'ack', options.consumerId)) return null;
      const now = options.now?.() ?? Date.now();
      if (!Number.isSafeInteger(now) || now < 0) return null;
      const bytes = new TextEncoder().encode(JSON.stringify(body));
      const nonce = encodeBase64Url(crypto.getRandomValues(new Uint8Array(24)));
      const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
      const timestampSeconds = Math.floor(now / 1000);
      const frame = canonicalAttestationFrame({ siteId: options.siteId, keyId: options.keyId, timestampSeconds,
        nonce, method: 'POST', route, bodyDigest: digest });
      const key = await crypto.subtle.importKey('raw', options.key.slice().buffer, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const signature = toHex(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(frame))));
      const request = new Request(`https://emdash.internal/${route}`, { method: 'POST', body: bytes,
        headers: { 'content-type': 'application/json', 'x-payment-site-id': options.siteId, 'x-payment-key-id': options.keyId,
          'x-payment-timestamp': String(timestampSeconds), 'x-payment-nonce': nonce, 'x-payment-signature': signature } });
      const result = fromRawHostExecution(await invoke(options.installedPluginId, route, request));
      return result.ok ? result.value : null;
    } catch { return null; }
  }
  return Object.freeze({
    async feed(limit = 50, cursor?: string): Promise<Feed | null> {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 50 || (cursor !== undefined &&
        (typeof cursor !== 'string' || cursor.length < 1 || cursor.length > 4096))) return null;
      const value = await call('results/feed', { consumerId: options.consumerId, limit, ...(cursor ? { cursor } : {}) });
      if (!isPlainObject(value) || !Array.isArray(value.items) || value.items.length > limit ||
        !value.items.every(isVerifiedPaymentResult) || (value.nextCursor !== undefined &&
        (typeof value.nextCursor !== 'string' || value.nextCursor.length < 1 || value.nextCursor.length > 4096))) return null;
      return { items: value.items, ...(typeof value.nextCursor === 'string' ? { nextCursor: value.nextCursor } : {}) };
    },
    async acknowledge(id: string): Promise<boolean> {
      if (!eventId.test(id)) return false;
      const value = await call('results/ack', { schemaVersion: '1.0', consumerId: options.consumerId,
        eventId: id, outcome: 'durably_handled' });
      return isPlainObject(value) && value.acknowledged === true && value.eventId === id;
    },
  });
}
