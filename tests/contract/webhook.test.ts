import { describe, expect, it } from 'vite-plus/test';
import { handlePaystackWebhook, MAX_PAYSTACK_WEBHOOK_BYTES } from '../../src/routes/webhook.js';
import { verifyPaystackTransaction } from '../../src/domain/verification.js';
import { createVerificationFixture, INTENT_ID, ATTEMPT_ID, REFERENCE, successData } from '../support/verification-fixture.js';
import { CURRENT_SECRET, eventBytes, MemoryInbox, OLD_SECRET, PROFILE, send, signature, URL, dependencies } from '../support/webhook-fixture.js';

describe('Paystack raw webhook and verification contracts', () => {
  it('TC-WHK-001 verifies HMAC-SHA512 over exact raw Unicode and whitespace bytes with a versioned profile', async () => {
    const raw = eventBytes('"status":"success","message":"Réussi ✓"', '\n ');
    const accepted = await send(raw, OLD_SECRET);
    expect(accepted.response).toEqual({ status: 200, body: 'accepted' });
    expect([...accepted.deps.inbox.entries.values()]).toEqual([
      expect.objectContaining({ profileId: PROFILE, credentialVersion: 1, state: 'accepted' }),
    ]);

    const signedOriginal = await signature(raw, OLD_SECRET);
    const changed = eventBytes('"status":"success","message":"Réussi ✓"');
    expect(await handlePaystackWebhook(changed, {
      method: 'POST', url: URL, headers: { 'x-paystack-signature': signedOriginal },
    }, accepted.deps.value)).toEqual({ status: 401, body: 'invalid signature' });
    expect(accepted.deps.inbox.writes).toBe(1);
  });

  it('TC-WHK-002 returns real raw statuses and rejects signature errors before decoding', async () => {
    const malformed = new TextEncoder().encode('{"event":');
    const invalidSignatureDeps = dependencies();
    const invalidSignature = await handlePaystackWebhook(malformed, {
      method: 'POST', url: URL, headers: { 'x-paystack-signature': 'f'.repeat(128) },
    }, invalidSignatureDeps.value);
    expect(invalidSignature).toEqual({ status: 401, body: 'invalid signature' });
    expect(invalidSignatureDeps.inbox.reads + invalidSignatureDeps.inbox.writes).toBe(0);

    const malformedJson = await send(malformed);
    expect(malformedJson.response).toEqual({ status: 400, body: 'invalid request' });

    const oversizedDeps = dependencies();
    const oversized = await handlePaystackWebhook(new Uint8Array(MAX_PAYSTACK_WEBHOOK_BYTES + 1), {
      method: 'POST', url: URL, headers: { 'x-paystack-signature': 'f'.repeat(128) },
    }, oversizedDeps.value);
    expect(oversized).toEqual({ status: 413, body: 'too large' });
    expect(oversizedDeps.settings.reads).toBe(0);

    const unavailableInbox = new MemoryInbox();
    unavailableInbox.throwRead = true;
    const unavailable = await send(eventBytes(), CURRENT_SECRET, dependencies({ inbox: unavailableInbox }));
    expect(unavailable.response).toEqual({ status: 503, body: 'unavailable' });
    expect(unavailable.deps.inbox.writes).toBe(0);
  });

  it('TC-WHK-003 deduplicates late or reversed events and never fulfills amount, currency, reference, environment, or customer mismatches', async () => {
    const first = await send(eventBytes());
    const repeated = await send(eventBytes('"status":"success"', '\n '), undefined, first.deps);
    expect(first.response.status).toBe(200);
    expect(repeated.response.status).toBe(200);
    expect(first.deps.inbox.writes).toBe(1);

    const paid = await createVerificationFixture();
    expect((await verifyPaystackTransaction({ intentId: INTENT_ID }, paid.dependencies)).kind).toBe('paid');
    expect((await verifyPaystackTransaction({ intentId: INTENT_ID, attemptId: ATTEMPT_ID,
      expectedReference: REFERENCE }, paid.dependencies)).kind).toBe('already_paid');
    expect((await verifyPaystackTransaction({ intentId: INTENT_ID, attemptId: ATTEMPT_ID,
      expectedResourceId: '999' }, paid.dependencies)).kind).toBe('review_required');
    expect(paid.fetches).toHaveLength(1);
    expect(paid.intents.writeCount).toBe(1);

    const late = await createVerificationFixture();
    const original = late.intents.value!;
    const predecessor = (original.attempts as Array<Record<string, unknown>>)[0]!;
    const successorId = `psk:v1:attempts:${'3'.repeat(64)}`;
    late.intents.value = {
      ...original, currentAttemptId: successorId, state: 'requires_action',
      attempts: [
        { ...predecessor, state: 'verified_failed', providerState: 'failed' },
        { ...predecessor, id: successorId, ordinal: 2, predecessorId: ATTEMPT_ID,
          state: 'requires_action', providerState: 'initialized', providerReference: 'psk-successor-reference',
          nextAction: { id: successorId, kind: 'redirect', destination: 'https://checkout.paystack.com/other' } },
      ],
    };
    expect((await verifyPaystackTransaction({ intentId: INTENT_ID, attemptId: ATTEMPT_ID }, late.dependencies)).kind)
      .toBe('review_required');
    expect(late.intents.value).toMatchObject({
      state: 'review_required', currentAttemptId: successorId, deliveryState: 'not_eligible',
      attempts: [{ state: 'review_required' }, { state: 'review_required', nextAction: null }],
    });
    expect(late.intents.value).not.toHaveProperty('resultEvent');
    expect((await verifyPaystackTransaction({ intentId: INTENT_ID, attemptId: successorId,
      forceVerification: true }, late.dependencies)).kind).toBe('review_required');
    expect(late.fetches).toHaveLength(1);
    expect(late.intents.writeCount).toBe(1);

    for (const patch of [
      { status: 'reversed' }, { amount: 500001 }, { currency: 'USD' }, { reference: 'psk-other-reference' },
      { domain: 'live' }, { customer: { id: 1001, email: 'someone-else@example.test' } },
    ]) {
      const mismatch = await createVerificationFixture({ provider: { ...successData(), ...patch } });
      expect((await verifyPaystackTransaction({ intentId: INTENT_ID }, mismatch.dependencies)).kind).toBe('review_required');
      expect(mismatch.intents.value).not.toHaveProperty('resultEvent');
    }
  });
});
