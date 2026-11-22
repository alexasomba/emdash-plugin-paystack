import { describe, expect, it } from 'vite-plus/test';
import { createDashcommercePaystackProvider } from '../../integrations/dashcommerce/provider.js';
import { signRelayBody } from '../../integrations/dashcommerce/relay.js';
describe('Core Paystack provider boundary', () => {
  it('authenticates exact relay bytes and rejects malformed events', async () => {
    const provider = createDashcommercePaystackProvider({ initialize: async () => ({ kind: 'pending', checkoutReference: 'x' }) });
    const body = JSON.stringify({ type: 'charge.succeeded', id: `psk:v1:results:${'a'.repeat(64)}`, orderDraftId: 'draft1',
      checkoutReference: `psk:v1:intents:${'b'.repeat(64)}`, paymentReference: 'ref-1', amount: 5000, currency: 'NGN' });
    const secret = 'ab'.repeat(32); const signatureHeader = await signRelayBody(body, secret);
    expect((await provider.verifyWebhook({ rawBody: body, signatureHeader, secret })).ok).toBe(true);
    expect((await provider.verifyWebhook({ rawBody: `${body} `, signatureHeader, secret })).ok).toBe(false);
    expect(provider.parseWebhookEvent(body).type).toBe('charge.succeeded');
    expect(provider.parseWebhookEvent(body.replace('5000', '4999')).type).toBe('unhandled');
    expect(provider.parseWebhookEvent('{}').type).toBe('unhandled');
  });
  it('does not initiate a payment without an orderable address', async () => {
    let calls = 0;
    const provider = createDashcommercePaystackProvider({ initialize: async () => { calls++; return { kind: 'pending', checkoutReference: 'x' }; } });
    await expect(provider.initCheckout({}, { orderDraftId: 'draft', amount: 5000, currency: 'NGN', customer: { email: 'a@b.co' }, successUrl: 'https://shop.example' }, {})).rejects.toThrow('address');
    expect(calls).toBe(0);
  });
});
