import { describe, expect, it } from 'vite-plus/test';
import { createDashcommerceIntegration } from '../../integrations/dashcommerce/index.js';
import { createVerifiedPaymentResult } from '../../src/domain/result.js';

describe('DashCommerce companion', () => {
  it('registers a provider and acknowledges only after Core confirms a bound result', async () => {
    const intentId = `psk:v1:intents:${'a'.repeat(64)}`;
    const event = await createVerifiedPaymentResult({ intentId, attemptId: `psk:v1:attempts:${'b'.repeat(64)}`,
      formId: 'form', formRevision: '1', environment: 'test', merchantProfile: 'merchant',
      amount: { currency: 'NGN', value: '50.00' }, verifiedAt: new Date().toISOString(), providerResourceId: '123', providerReference: 'reference' });
    const rows = new Map<string, unknown>(); let ack = 0, fail = true;
    const config = { checkout: { installedPluginId: 'plugin', siteId: 'site', keyId: 'sitekey', attestationKey: new Uint8Array(32).fill(1),
      merchantProfile: 'merchant', environment: 'test' as const, formId: 'form', formRevision: '1', siteOrigin: 'https://shop.example' },
      resultClient: { installedPluginId: 'plugin', siteId: 'site', consumerId: 'consumer', keyId: 'resultkey', key: new Uint8Array(32).fill(2),
        consumeQuota: async () => true, invoke: async (_id: string, route: string) => ({ success: true, data: { ok: true,
          value: route === 'results/feed' ? { items: [event], nextCursor: 'next' } : (ack++, { eventId: event.eventId, acknowledged: true }) } }) },
      bindings: { getVersioned: async (key: string) => rows.has(key) ? { value: rows.get(key), revision: '1' } : null,
        compareAndSet: async (key: string, _rev: string | null, value: unknown) => { rows.set(key, value); return { applied: true }; } },
      relaySecret: '03'.repeat(32), deliver: async (_body: string, signature: string) => {
        expect(signature).toMatch(/^[a-f0-9]{64}$/u); return new Response(JSON.stringify(fail ? { error: 'recovery' } : { received: true }), { status: fail ? 503 : 200 }); },
    };
    rows.set(`paystack-intent-binding:${intentId}`, { intentId, orderDraftId: 'draft', amount: 5000, currency: 'NGN', environment: 'test' });
    const integration = createDashcommerceIntegration(config);
    let registered = '';
    integration.register((p) => { registered = p.id; });
    expect(registered).toBe('paystack');
    expect(await integration.provider.getCredentials?.()).toEqual({ secretKey: 'host-managed-paystack', webhookSecret: config.relaySecret });
    expect(await integration.poll()).toEqual({ acknowledged: 0, retry: 1, rejected: 0, nextCursor: 'next' });
    expect(ack).toBe(0);
    fail = false;
    expect(await integration.poll()).toEqual({ acknowledged: 1, retry: 0, rejected: 0, nextCursor: 'next' });
    expect(ack).toBe(1);
    expect(() => createDashcommerceIntegration({ ...config, relaySecret: '01'.repeat(32) })).toThrow('INVALID_DASHCOMMERCE_CONFIGURATION');
    expect(() => createDashcommerceIntegration({ ...config, resultClient: { ...config.resultClient, siteId: 'different' } })).toThrow('INVALID_DASHCOMMERCE_CONFIGURATION');
    let attempted = 0;
    const unavailable = createDashcommerceIntegration({ ...config,
      checkout: { ...config.checkout, invoke: async () => { attempted++; return null; } },
      resultClient: { ...config.resultClient, consumeQuota: async () => false } });
    await expect(unavailable.provider.initCheckout({}, { orderDraftId: 'draft', amount: 5000, currency: 'NGN',
      customer: { email: 'payer@example.com' }, successUrl: 'https://shop.example/thank-you/draft',
      billingAddress: { line1: 'One Street', city: 'Lagos', country: 'NG' } }, {})).rejects.toThrow('unavailable');
    expect(attempted).toBe(0);
  });
});
