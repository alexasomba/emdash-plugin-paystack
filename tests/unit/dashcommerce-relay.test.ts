import { describe, expect, it } from 'vite-plus/test';
import { createVerifiedPaymentResult } from '../../src/domain/result.js';
import { relayVerifiedResult, signRelayBody } from '../../integrations/dashcommerce/relay.js';

describe('DashCommerce result relay', () => {
  it('acks only after successful Core handling and retries uncertain outcomes', async () => {
    const intentId = `psk:v1:intents:${'a'.repeat(64)}`;
    const result = await createVerifiedPaymentResult({ intentId, attemptId: `psk:v1:attempts:${'b'.repeat(64)}`,
      formId: 'checkout', formRevision: '1', environment: 'test', merchantProfile: 'shop',
      amount: { currency: 'NGN', value: '50.00' }, verifiedAt: new Date().toISOString(), providerResourceId: '123', providerReference: 'ref-1' });
    let acks = 0; let deliveries = 0;
    const options = { merchantProfile: 'shop', formId: 'checkout', formRevision: '1', secret: 'ab'.repeat(32),
      binding: async () => ({ intentId, orderDraftId: 'draft1', amount: 5000, currency: 'NGN' as const, environment: 'test' as const }),
      deliver: async (body: string, signature: string) => { deliveries++; expect(signature).toBe(await signRelayBody(body, 'ab'.repeat(32)));
        return new Response(JSON.stringify({ received: true }), { status: 200 }); },
      acknowledge: async () => { acks++; return true; } };
    expect(await relayVerifiedResult(result, { ...options, deliver: async () => new Response('{}', { status: 503 }) })).toBe('retry');
    expect(await relayVerifiedResult(result, { ...options, deliver: async () => { throw new Error('lost response'); } })).toBe('retry');
    expect(await relayVerifiedResult(result, { ...options, deliver: async () => new Response('{"received":true,"skipped":true}') })).toBe('retry');
    expect(acks).toBe(0);
    expect(await relayVerifiedResult(result, { ...options, binding: async () => ({ ...(await options.binding()), amount: 5001 }) })).toBe('rejected');
    expect(deliveries).toBe(0);
    expect(await relayVerifiedResult(result, options)).toBe('acknowledged');
    expect(acks).toBe(1);
    expect(await relayVerifiedResult(result, { ...options, acknowledge: async () => false })).toBe('retry');
  });
});
