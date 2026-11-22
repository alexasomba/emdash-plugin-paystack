import { describe, expect, it } from 'vite-plus/test';
import { createFixture, makeTrustedBody, invoke } from '../support/site-admission-fixture.js';
import type { AdmissionIntentRecord } from '../../src/storage/admission.js';

describe('payment intent admission and deduplication contracts', () => {
  it('TC-INT-001 rejects every payer-controlled protected price field before deduplication or provider I/O', async () => {
    const fixture = await createFixture();
    for (const [index, field] of ['amount', 'currency', 'pricing', 'pricingPolicy', 'resolvedOrderPrice', 'payerAmount'].entries()) {
      const body = makeTrustedBody();
      const result = await invoke(fixture.dependencies, { ...body, submission: { ...body.submission, [field]: '50.00' } },
        `contract_override_nonce_${index}`);
      expect(result).toMatchObject({ ok: false, error: { code: 'protected_field_override' } });
    }
    expect(fixture.requestKeys.writeCount).toBe(0);
    expect(fixture.intents.writeCount).toBe(0);
  });

  it('TC-INT-002 returns the existing intent across fresh keys but binds an exact historical request key', async () => {
    const fixture = await createFixture();
    const original = makeTrustedBody();
    await invoke(fixture.dependencies, original, 'contract_history_admit_01');
    await invoke(fixture.dependencies, original, 'contract_history_mid_01');
    await invoke(fixture.dependencies, original, 'contract_history_alloc_01');
    const intent = fixture.intents.values()[0]!;
    const first = intent.attempts[0]!;
    const duplicate = await invoke(fixture.dependencies, makeTrustedBody('contract_history_duplicate'), 'contract_history_dup_01');
    expect(duplicate).toMatchObject({ ok: true, value: { intentId: intent.identityHmac, attemptId: first.id, outcome: 'existing_intent' } });

    // Seed a later successor to test replay independently of Paystack failure finality.
    const successorId = `psk:v1:attempts:${'e'.repeat(64)}`;
    fixture.intents.seed(intent.identityHmac, { ...intent, currentAttemptId: successorId,
      attempts: [{ ...first, state: 'verified_failed', providerState: 'failed' },
        { ...first, id: successorId, ordinal: 2, predecessorId: first.id }],
    } as unknown as AdmissionIntentRecord);
    expect(await invoke(fixture.dependencies, original, 'contract_history_original_1')).toMatchObject({ ok: true, value: {
      intentId: intent.identityHmac, attemptId: first.id, state: 'verified_failed', outcome: 'existing_intent',
    } });
    expect(await invoke(fixture.dependencies, makeTrustedBody('contract_history_latest'), 'contract_history_latest_01')).toMatchObject({
      ok: true, value: { intentId: intent.identityHmac, attemptId: successorId, outcome: 'existing_intent' },
    });
    expect(fixture.intents.values()[0]?.attempts).toHaveLength(2);
  });

  it('TC-INT-003 serializes different-key concurrent admission and archive replay to one attempt', async () => {
    const fixture = await createFixture();
    const submit = (key: string, nonce: string) => invoke(fixture.dependencies, makeTrustedBody(key), nonce);
    const keys = ['contract_request_key_A', 'contract_request_key_B'];
    await Promise.all(keys.map((key, index) => submit(key, `contract_parallel_first_${index}`)));
    for (let step = 0; step < 3; step++) {
      await Promise.all(keys.map((key, index) => submit(key, `contract_parallel_${step}_${index}`)));
    }
    expect(fixture.intents.values()).toHaveLength(1);
    const intent = fixture.intents.values()[0]!;
    expect(intent.attempts).toHaveLength(1);
    expect(fixture.requestKeys.values().map((record) => record.attemptId)).toEqual([intent.currentAttemptId, intent.currentAttemptId]);
    const form = fixture.forms.values()[0]!;
    fixture.forms.seed(form.definition.id, { ...form, state: 'archived', definition: { ...form.definition, state: 'archived' } });
    expect(await submit(keys[0]!, 'contract_archive_replay_01')).toMatchObject({ ok: true, value: { intentId: intent.identityHmac,
      attemptId: intent.currentAttemptId, outcome: 'existing_intent' } });
  });
});
