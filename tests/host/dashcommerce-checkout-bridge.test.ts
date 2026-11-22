import { afterEach, beforeEach, describe, expect, it } from 'vite-plus/test';
import { createPluginRuntimeTestHost, type PluginRuntimeTestHost } from '@emdash-cms/plugin-test';
import { createDashcommerceCheckoutBridge, type CheckoutBinding } from '../../integrations/dashcommerce/checkout-bridge.js';
import { encodeBase64Url } from '../../src/security/encryption.js';
import { createPaystackReference } from '../../src/provider/paystack-reference.js';
import { schedulerHealthId } from '../../src/storage/scheduler-health.js';
const checkoutForm = { id: 'dashcommerce_checkout', revision: '1' };

let host: PluginRuntimeTestHost;
let admin: Awaited<ReturnType<PluginRuntimeTestHost['fixtures']['user']>>;
const siteKey = new Uint8Array(32).fill(3);
const encode = (n: number) => encodeBase64Url(new Uint8Array(32).fill(n));

describe('DashCommerce bridge through the EmDash sandbox runtime', () => {
  beforeEach(async () => {
    host = await createPluginRuntimeTestHost();
    admin = await host.fixtures.user({ email: 'checkout-bridge-admin@example.test', role: 'admin' });
    await host.fixtures.plugin.setting('paymentConfiguration', JSON.stringify({ schemaVersion: 1, paused: false,
      activeProfile: 'merchant', profiles: { merchant: { profileId: 'merchant', activeCredentialVersion: 1,
        credentialVersions: [{ version: 1, environment: 'test', secretKey: 'sk_test_bridge_fixture' }] } },
      integrationKeys: [{ siteId: 'site', keyId: 'key', purpose: 'site-payment', secretBase64url: encodeBase64Url(siteKey) }],
      fieldEncryptionKeyRing: { activeKeyId: 'field-v1', keys: [{ keyId: 'field-v1', material: encode(4) }] },
      identityHmacKeyRing: { activeKeyId: 'identity-v1', keys: [{ keyId: 'identity-v1', material: encode(5) }] },
    }));
    await host.fixtures.plugin.storage('budgets', schedulerHealthId(), {
      modelVersion: 1, healthKind: 'paystack-reconciliation-scheduler', leaseEpoch: 0, lease: null,
      lastSuccessfulAt: Date.now(), oldestDueIntentAt: null, oldestDueInboxAt: null, nextQueue: 'intents',
      providerCooldownUntil: 0, providerCooldownObservedAt: null, expiresAt: Number.MAX_SAFE_INTEGER,
    });
    const provision = { method: 'POST' as const, headers: { 'x-emdash-request': '1' },
      body: { action: 'provision', formId: checkoutForm.id }, user: admin };
    for (let attempt = 0; attempt < 2; attempt++) {
      const response = await host.actions.routes.request('forms', provision);
      expect(response.status).toBe(200);
      expect(await response.json()).toMatchObject({ success: true, data: { ok: true,
        value: { form: { ...checkoutForm, state: 'published', pricing: { mode: 'trusted_order' } } } } });
    }
  });
  afterEach(async () => { await host?.dispose(); });
  it('refuses to bind a draft or start provider work when the persisted environment differs', async () => {
    const bindings: CheckoutBinding[] = [];
    const bridge = createDashcommerceCheckoutBridge({ installedPluginId: host.manifest.id, siteId: 'site', keyId: 'key',
      attestationKey: siteKey, merchantProfile: 'merchant', environment: 'live', formId: checkoutForm.id,
      formRevision: checkoutForm.revision, siteOrigin: 'https://shop.example', bind: async (binding) => { bindings.push(binding); return true; },
      invoke: async (_id, path, request) => {
        const headers = Object.fromEntries(request.headers.entries());
        const response = await host.actions.routes.request(path, { method: 'POST', rawBody: new Uint8Array(await request.arrayBuffer()),
          user: admin, headers: { ...headers, 'x-emdash-request': '1' } });
        return response.json();
      },
    });
    const result = await bridge.initialize({ orderDraftId: 'draft_wrong', amount: 500_000, currency: 'NGN',
      customer: { email: 'payer@example.test' }, successUrl: 'https://shop.example/thank-you/draft_wrong', mode: 'payment' });
    expect(result.kind).toBe('unavailable');
    expect(bindings).toHaveLength(0);
    const form = await host.inspect.storage.get<Record<string, unknown>>('forms', checkoutForm.id);
    expect(form?.admissionSequence).toBe(0);
    expect(host.http.requests()).toHaveLength(0);
  });

  it('binds the intent before one provider request and resumes the same redirect on replay', async () => {
    const bindings = new Map<string, CheckoutBinding>();
    const bridge = createDashcommerceCheckoutBridge({ installedPluginId: host.manifest.id, siteId: 'site', keyId: 'key',
      attestationKey: siteKey, merchantProfile: 'merchant', environment: 'test', formId: checkoutForm.id,
      formRevision: checkoutForm.revision, siteOrigin: 'https://shop.example',
      bind: async (binding) => {
        const prior = bindings.get(binding.intentId);
        if (prior && JSON.stringify(prior) !== JSON.stringify(binding)) return false;
        if (!prior) {
          bindings.set(binding.intentId, binding);
          await host.http.respond('https://api.paystack.co/transaction/initialize', new Response(JSON.stringify({ status: true,
            data: { reference: createPaystackReference(binding.intentId, 1), authorization_url: 'https://checkout.paystack.com/checkout_123' } }),
            { status: 200, headers: { 'content-type': 'application/json' } }));
        }
        return true;
      },
      invoke: async (_id, path, request) => {
        const headers = Object.fromEntries(request.headers.entries());
        const response = await host.actions.routes.request(path, { method: 'POST', rawBody: new Uint8Array(await request.arrayBuffer()),
          user: admin, headers: { ...headers, 'x-emdash-request': '1' } });
        return response.json();
      },
    });
    const input = { orderDraftId: 'draft_1', amount: 500_000, currency: 'NGN', customer: { email: 'payer@example.test' },
      successUrl: 'https://shop.example/thank-you/draft_1?session_id={CHECKOUT_SESSION_ID}', mode: 'payment' as const };
    const first = await bridge.initialize(input);
    expect(first).toMatchObject({ kind: 'redirect', redirectUrl: 'https://checkout.paystack.com/checkout_123' });
    expect(bindings.size).toBe(1);
	const binding = [...bindings.values()][0]!;
	const intent = await host.inspect.storage.get<Record<string, unknown>>('intents', binding.intentId);
	expect(intent).toMatchObject({ state: 'requires_action', nextRunAt: expect.any(Number) });
	expect(intent!.nextRunAt as number).toBeLessThan(Number.MAX_SAFE_INTEGER);
    expect(host.http.requests()).toHaveLength(1);
    const providerBody = JSON.parse(new TextDecoder().decode(host.http.requests()[0]!.body));
    expect(providerBody).toMatchObject({ email: 'payer@example.test', amount: '500000', currency: 'NGN',
      channels: ['card'], callback_url: 'https://shop.example/thank-you/draft_1' });
    expect(providerBody).toEqual(expect.objectContaining({ reference: expect.any(String) }));
    expect(Object.keys(providerBody).sort()).toEqual(['amount', 'callback_url', 'channels', 'currency', 'email', 'reference']);
    expect(await bridge.initialize(input)).toEqual(first);
    expect(host.http.requests()).toHaveLength(1);
  });
});
