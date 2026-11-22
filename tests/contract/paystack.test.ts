import { describe, expect, it } from 'vite-plus/test';
import { createFixture, makeTrustedBody, invoke, invokeAction } from '../support/site-admission-fixture.js';
import { parsePaystackCheckoutUrl } from '../../src/provider/paystack.js';
import { safeActionErrorCode } from '../../src/routes/actions.js';
import { parseSitePaymentStatus } from '../../examples/astro-site/payer-form/client.js';

describe('Paystack hosted-card adapter contracts', () => {
  it('TC-PSK-001 initializes NGN hosted card with only email, minor-unit amount, reference, callback, and card channel', async () => {
    const { start, request } = await checkoutFixture();
    let transmissions = 0;
    const result = await start('contract_init_nonce_01', async (url, init) => {
      transmissions++;
      expect(url).toBe('https://api.paystack.co/transaction/initialize');
      expect(init?.method).toBe('POST');
      const payload = JSON.parse(String(init?.body));
      expect(payload).toEqual({ email: 'payer@example.test', amount: '500000', currency: 'NGN',
        reference: expect.stringMatching(/^psk-[a-f0-9]{64}-1$/u), callback_url: request.callbackUrl, channels: ['card'] });
      return new Response(JSON.stringify({ status: true, data: { reference: payload.reference,
        authorization_url: 'https://checkout.paystack.com/session' } }), { headers: { 'content-type': 'application/json' } });
    });
    expect(result).toMatchObject({ ok: true, value: { state: 'requires_action', nextAction: {
      id: request.attemptId, kind: 'redirect', destination: 'https://checkout.paystack.com/session' } } });
    expect(transmissions).toBe(1);
  });

  it('TC-PSK-002 accepts only the exact HTTPS Paystack checkout host with no credentials', () => {
    expect(parsePaystackCheckoutUrl('https://checkout.paystack.com/session')).toBe('https://checkout.paystack.com/session');
    for (const url of ['http://checkout.paystack.com/session', 'https://checkout.paystack.com.attacker.test/session',
      'https://user@checkout.paystack.com/session']) expect(parsePaystackCheckoutUrl(url)).toBeNull();
  });

  it('TC-PSK-003 preserves unknown after 429, 5xx, malformed responses, and late acceptance without retransmission', async () => {
    const outcomes = [
      () => new Response('{}', { status: 429 }),
      () => new Response('{}', { status: 503 }),
      () => new Response('{', { headers: { 'content-type': 'application/json' } }),
    ];
    for (const outcome of outcomes) {
      const { start, fixture } = await checkoutFixture();
      let transmissions = 0;
      const fetch = async () => { transmissions++; return outcome(); };
      expect(await start('contract_unknown_nonce_1', fetch)).toMatchObject({ ok: true, value: { state: 'unknown' } });
      expect(await start('contract_unknown_nonce_2', fetch)).toMatchObject({ ok: true, value: { state: 'unknown' } });
      expect(fixture.intents.values()[0]?.attempts[0]).toMatchObject({ createTransmissionStarted: true, state: 'unknown' });
      expect(transmissions).toBe(1);
    }
    const { start } = await checkoutFixture();
    let transmissions = 0;
    let complete!: (response: Response) => void;
    let reference = '';
    const fetch = async (_url: string, init?: RequestInit) => {
      transmissions++;
      reference = JSON.parse(String(init?.body)).reference;
      return new Promise<Response>((resolve) => { complete = resolve; });
    };
    expect(await start('contract_late_nonce_001', fetch)).toMatchObject({ ok: true, value: { state: 'unknown' } });
    complete(new Response(JSON.stringify({ status: true, data: { reference,
      authorization_url: 'https://checkout.paystack.com/session' } }), { headers: { 'content-type': 'application/json' } }));
    expect(await start('contract_late_nonce_002', fetch)).toMatchObject({ ok: true, value: { state: 'unknown' } });
    expect(transmissions).toBe(1);
  }, 15_000);

  it('TC-PSK-004 requires the discriminated next-action field and maps aliases into the finite error vocabulary', () => {
    const attemptId = `psk:v1:attempts:${'a'.repeat(64)}`;
    const input = { schemaVersion: '1.0', intentId: `psk:v1:intents:${'b'.repeat(64)}`, attemptId,
      state: 'requires_action', deliveryState: 'not_eligible', nextAction: { id: attemptId, kind: 'redirect',
        instructions: 'wrong-branch', destination: 'https://checkout.paystack.com/session' } };
    expect(parseSitePaymentStatus(input)).toBeNull();
    expect(['unsupported_action', 'temporary_unavailable', 'capacity_exceeded'].map(safeActionErrorCode))
      .toEqual(['review_required', 'provider_unavailable', 'review_required']);
  });
});

async function checkoutFixture() {
  const fixture = await createFixture();
  const body = makeTrustedBody();
  await invoke(fixture.dependencies, body, 'contract_provider_admit_1');
  await invoke(fixture.dependencies, body, 'contract_provider_middle_1');
  await invoke(fixture.dependencies, body, 'contract_provider_alloc_1');
  const intent = fixture.intents.values()[0]!;
  const attempt = intent.attempts[0]!;
  const request = { schemaVersion: '1.0', siteId: body.siteId, subject: body.subject,
    merchantProfile: body.merchantProfile, intentId: intent.identityHmac, attemptId: attempt.id, actionId: attempt.id,
    siteOrigin: 'https://shop.example', callbackUrl: 'https://shop.example/payments/return' };
  return { fixture, request, start: (nonce: string, fetch: (url: string, init?: RequestInit) => Promise<Response>) => invokeAction(fixture, request, nonce, {
    settings: fixture.dependencies.settings, intents: fixture.intents, budgets: fixture.budgets, fetch,
    now: fixture.dependencies.now!, randomBytes: (length) => new Uint8Array(length).fill(16),
  }) };
}
