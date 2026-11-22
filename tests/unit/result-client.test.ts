import { describe, expect, it } from 'vite-plus/test';
import { createResultClient } from '../../examples/astro-site/result-consumer/client.js';
import { verifySiteAttestation } from '../../src/security/attestation.js';
import { createVerifiedPaymentResult } from '../../src/domain/result.js';

const key = new Uint8Array(32).fill(9);
const now = 120_000;
const eventId = `psk:v1:results:${'c'.repeat(64)}`;
describe('server result client', () => {
  it('signs only the fixed feed and ack routes with the consumer key', async () => {
    const calls: string[] = [];
    const payment = await createVerifiedPaymentResult({ intentId: `psk:v1:intents:${'a'.repeat(64)}`,
      attemptId: `psk:v1:attempts:${'b'.repeat(64)}`, formId: 'form', formRevision: '1', environment: 'test',
      merchantProfile: 'merchant', amount: { currency: 'NGN', value: '5000.00' }, verifiedAt: '2026-10-18T00:00:00.000Z',
      providerResourceId: '123', providerReference: 'reference' });
    const client = createResultClient({ installedPluginId: 'plugin_id', siteId: 'site', consumerId: 'consumer', keyId: 'key', key,
      now: () => now, consumeQuota: async () => true, invoke: async (id, route, request) => {
        expect(id).toBe('plugin_id'); calls.push(route);
        const rawBody = new Uint8Array(await request.arrayBuffer());
        const headers = Object.fromEntries(request.headers.entries());
        expect(await verifySiteAttestation({ provider: 'paystack', method: 'POST', route, rawBody, headers, nowMs: now,
          keys: [{ provider: 'paystack', siteId: 'site', keyId: 'key', purpose: 'result-consumer', material: key, state: 'current' }] })).not.toBeNull();
        const body = JSON.parse(new TextDecoder().decode(rawBody));
        expect(body.consumerId).toBe('consumer');
        return { success: true, data: { ok: true, value: route === 'results/feed' ? { items: [payment] } : { eventId, acknowledged: true } } };
      } });
    expect((await client.feed())?.items).toEqual([payment]);
    expect(await client.acknowledge(eventId)).toBe(true);
    expect(calls).toEqual(['results/feed', 'results/ack']);
  });
  it('fails closed on quota denial, malformed results and invalid acknowledgement identities', async () => {
    let calls = 0;
    const opts = { installedPluginId: 'plugin', siteId: 'site', consumerId: 'consumer', keyId: 'key', key,
      consumeQuota: async () => false, invoke: async () => { calls++; return { success: true, data: { ok: true, value: {} } }; } };
    const denied = createResultClient(opts);
    expect(await denied.feed()).toBeNull();
    expect(await denied.acknowledge('invalid')).toBe(false);
    expect(calls).toBe(0);
    const malformed = createResultClient({ ...opts, consumeQuota: async () => true });
    expect(await malformed.feed()).toBeNull();
    expect(await malformed.acknowledge(eventId)).toBe(false);
  });
});
