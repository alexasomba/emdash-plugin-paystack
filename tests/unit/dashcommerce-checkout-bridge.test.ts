import { describe, expect, it } from 'vite-plus/test';
import { createDashcommerceCheckoutBridge, type CheckoutBridgeOptions, type CoreCheckout } from '../../integrations/dashcommerce/checkout-bridge.js';
import { verifySiteAttestation } from '../../src/security/attestation.js';

const intentId = `psk:v1:intents:${'a'.repeat(64)}`;
const attemptId = `psk:v1:attempts:${'b'.repeat(64)}`;
const key = new Uint8Array(32).fill(8), now = 120_000;
const input: CoreCheckout = { orderDraftId: 'draft_1', amount: 500_000, currency: 'NGN',
  customer: { email: 'payer@example.test' }, successUrl: 'https://shop.example/thank-you', mode: 'payment' };
function setup(overrides: Partial<CheckoutBridgeOptions> = {}, initializingStages = 1) {
  const calls: string[] = []; let bound = false, submits = 0;
  const options: CheckoutBridgeOptions = { installedPluginId: 'plugin', siteId: 'site', keyId: 'key', attestationKey: key,
    merchantProfile: 'merchant', environment: 'test', formId: 'shop', formRevision: '1', siteOrigin: 'https://shop.example',
    now: () => now, bind: async (binding) => { expect(binding).toMatchObject({ intentId, orderDraftId: 'draft_1', amount: 500_000 }); bound = true; return true; },
    invoke: async (_id, path, request) => {
      calls.push(path);
      const bytes = new Uint8Array(await request.arrayBuffer());
      const headers = Object.fromEntries(request.headers.entries());
      expect(await verifySiteAttestation({ provider: 'paystack', method: 'POST', route: path, rawBody: bytes, headers, nowMs: now,
        keys: [{ provider: 'paystack', siteId: 'site', keyId: 'key', purpose: 'site-payment', material: key, state: 'current' }] })).not.toBeNull();
      const body = JSON.parse(new TextDecoder().decode(bytes));
      if (path === 'payments/submit') {
        expect(body.expectedEnvironment).toBe('test');
        expect(body.resolvedOrderPrice).toEqual({ currency: 'NGN', value: '5000.00' });
        expect(body.submission.requestKey).toBe('draft_1');
        return { success: true, data: { ok: true, value: ++submits <= initializingStages ? { intentId, state: 'initializing' } : { intentId, attemptId, state: 'created' } } };
      }
      expect(bound).toBe(true);
      return { success: true, data: { ok: true, value: { intentId, attemptId, state: 'requires_action',
        nextAction: { id: attemptId, kind: 'redirect', destination: 'https://checkout.paystack.com/abc' } } } };
    }, ...overrides };
  return { bridge: createDashcommerceCheckoutBridge(options), calls };
}
describe('DashCommerce sandbox checkout bridge', () => {
  it('signs bounded stages and durably binds the intent before starting checkout', async () => {
    const f = setup();
    expect(await f.bridge.initialize(input)).toEqual({ kind: 'redirect', checkoutReference: intentId, redirectUrl: 'https://checkout.paystack.com/abc' });
    expect(f.calls).toEqual(['payments/submit', 'payments/submit', 'payments/action']);
  });
  it('resumes a three-stage admission while retaining the same durable binding', async () => {
    const f = setup({}, 2);
    expect(await f.bridge.initialize(input)).toEqual({ kind: 'redirect', checkoutReference: intentId, redirectUrl: 'https://checkout.paystack.com/abc' });
    expect(f.calls).toEqual(['payments/submit', 'payments/submit', 'payments/submit', 'payments/action']);
  });
  it('returns pending when admission remains unresolved after three stages', async () => {
    const f = setup({}, 3);
    expect(await f.bridge.initialize(input)).toEqual({ kind: 'pending', checkoutReference: intentId });
    expect(f.calls).toEqual(['payments/submit', 'payments/submit', 'payments/submit']);
  });
  it('does not start provider work when the durable order binding fails', async () => {
    const f = setup({ bind: async () => false });
    expect(await f.bridge.initialize(input)).toEqual({ kind: 'unavailable' });
    expect(f.calls).toEqual(['payments/submit']);
  });
  it('refuses unsupported currency, subscription, cross-site callbacks and payment features', async () => {
    const f = setup();
    for (const patch of [{ currency: 'USD' }, { mode: 'subscription' as const }, { successUrl: 'https://evil.example/' }, { automaticTax: true }]) {
      expect(await f.bridge.initialize({ ...input, ...patch })).toEqual({ kind: 'unavailable' });
    }
    expect(f.calls).toEqual([]);
  });
});
