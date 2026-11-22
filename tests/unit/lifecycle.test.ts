import { describe, expect, it } from 'vite-plus/test';
import { createFixture, invoke, invokeAction, makeTrustedBody } from '../support/site-admission-fixture.js';
import { PAYMENT_CONFIGURATION_SETTING, parseStoredPaymentConfiguration } from '../../src/domain/configuration.js';
import { createDataEncryptionKey, decryptValue, encryptValue, rotateEncryptedEnvelope } from '../../src/security/encryption.js';
import { verifySiteAttestation, type SiteAttestationKey } from '../../src/security/attestation.js';
import { PersistentCasStore, RpcLedger } from '../support/driver.js';

describe('profile rotation, retention, and erasure contracts', () => {
  it('TC-LIF-001 binds historical work to its original provider account and environment across profile changes', async () => {
    const fixture = await createFixture();
    const body = makeTrustedBody();
    const before = await fixture.dependencies.settings.getVersioned<string>(PAYMENT_CONFIGURATION_SETTING);
    await invoke(fixture.dependencies, body, 'contract_rotation_admission');
    await invoke(fixture.dependencies, body, 'contract_rotation_admit_middle');
    expect(fixture.requestKeys.values()[0]?.stage).toBe('admitted');

    expect(await fixture.setCredential(body.merchantProfile, 'live', 'sk_live_rotation_fixture')).toMatchObject({ ok: true });
    expect(await fixture.setCredential('merchant_profile_2', 'live', 'sk_live_new_account_fixture')).toMatchObject({ ok: true });
    const after = await fixture.dependencies.settings.getVersioned<string>(PAYMENT_CONFIGURATION_SETTING);
    expect(parseStoredPaymentConfiguration(JSON.parse(after!.value))?.identityHmacKeyRing)
      .toEqual(parseStoredPaymentConfiguration(JSON.parse(before!.value))?.identityHmacKeyRing);
    expect(parseStoredPaymentConfiguration(JSON.parse(after!.value))?.activeProfile).toBe('merchant_profile_2');

    // Allocation starts after the switch and still uses the admitted test credential.
    expect(await invoke(fixture.dependencies, body, 'contract_rotation_allocation')).toMatchObject({
      ok: true, value: { outcome: 'new_attempt' },
    });
    const original = fixture.intents.values()[0]!;
    expect(original).toMatchObject({ merchantProfile: body.merchantProfile, credentialVersion: 1, environment: 'test' });
    const attemptId = original.currentAttemptId;
    const headers: string[] = [];
    expect(await invokeAction(fixture, {
      schemaVersion: '1.0', siteId: body.siteId, subject: body.subject, merchantProfile: body.merchantProfile,
      intentId: original.identityHmac, attemptId, actionId: attemptId,
      siteOrigin: 'https://shop.example', callbackUrl: 'https://shop.example/payments/return',
    }, 'contract_rotation_action', {
      settings: fixture.dependencies.settings,
      intents: fixture.intents,
      budgets: fixture.budgets,
      now: fixture.dependencies.now!,
      randomBytes: (length) => new Uint8Array(length).fill(16),
      fetch: async (_url, init) => {
        headers.push(new Headers(init?.headers).get('authorization') ?? '');
        const { reference } = JSON.parse(String(init?.body));
        return Response.json({
          status: true, data: { reference, authorization_url: 'https://checkout.paystack.com/checkout_123' },
        });
      },
    })).toMatchObject({ ok: true, value: { state: 'requires_action' } });
    expect(headers).toEqual(['Bearer sk_test_admission_fixture']);

    expect(await invoke(fixture.dependencies, body, 'contract_rotation_retry')).toMatchObject({
      ok: true, value: { intentId: original.identityHmac, attemptId, outcome: 'existing_intent' },
    });
    expect(await invoke(fixture.dependencies, { ...body, subject: { kind: 'member', id: 'unrelated' } },
      'contract_rotation_unrelated')).toMatchObject({ ok: false, error: { code: 'request_key_conflict' } });
    const newBody = { ...makeTrustedBody('contract_rotation_new_key'), merchantProfile: 'merchant_profile_2' };
    await invoke(fixture.dependencies, newBody, 'contract_rotation_new_admission');
    await invoke(fixture.dependencies, newBody, 'contract_rotation_new_middle');
    await invoke(fixture.dependencies, newBody, 'contract_rotation_new_allocation');
    expect(fixture.intents.values()[1]).toMatchObject({ merchantProfile: newBody.merchantProfile, environment: 'live' });
  });

  it('TC-LIF-002 retains old keys across bounded re-encryption batches and retires only after the last reference', async () => {
    const oldKey = createDataEncryptionKey('field-v1', new Uint8Array(32).fill(1));
    const nextKey = createDataEncryptionKey('field-v2', new Uint8Array(32).fill(2));
    const keyRing = new Map([[oldKey.keyId, oldKey], [nextKey.keyId, nextKey]]);
    const rows = await Promise.all(Array.from({ length: 4 }, async (_value, index) => {
      const recordId = `intent_${String(index + 1).padStart(2, '0')}`;
      const context = { pluginId: 'emdash-plugin-paystack', collection: 'intents', recordId, schemaVersion: 1, purpose: 'custom_fields' as const };
      return { recordId, context, envelope: await encryptValue({ index, email: `payer-${index}@example.test` }, oldKey, context) };
    }));
    const durableRows = new Map(rows.map((row) => [row.recordId, row.envelope]));
    const batchLimit = 2;
    let checkpoint = 0;

    const firstBatch = rows.slice(checkpoint, checkpoint + batchLimit);
    for (const row of firstBatch) {
      durableRows.set(row.recordId, await rotateEncryptedEnvelope(row.envelope, keyRing, nextKey, row.context));
    }
    checkpoint += firstBatch.length;
    expect([...durableRows.values()].filter((envelope) => envelope.keyId === oldKey.keyId)).toHaveLength(2);
    expect(keyRing.has(oldKey.keyId)).toBe(true);

    // Resume from the persisted cursor after a restart; old-key rows remain readable until migrated.
    for (const row of rows.slice(checkpoint, checkpoint + batchLimit)) {
      const current = durableRows.get(row.recordId)!;
      expect(await decryptValue(current, keyRing, row.context)).toMatchObject({ email: `payer-${Number(row.recordId.slice(-2)) - 1}@example.test` });
      durableRows.set(row.recordId, await rotateEncryptedEnvelope(current, keyRing, nextKey, row.context));
    }
    checkpoint = rows.length;
    expect(checkpoint).toBe(4);
    expect([...durableRows.values()].every((envelope) => envelope.keyId === nextKey.keyId)).toBe(true);

    const retiredKeyRing = new Map([[nextKey.keyId, nextKey]]);
    for (const row of rows) {
      expect(await decryptValue(durableRows.get(row.recordId), retiredKeyRing, row.context)).toMatchObject({
        email: `payer-${Number(row.recordId.slice(-2)) - 1}@example.test`,
      });
    }
  });

  it('TC-LIF-003 rejects payment-only authorization for privacy erasure and preserves pending money, results, and dedup fences', async () => {
    const ledger = new RpcLedger();
    const store = new PersistentCasStore(ledger);
    const pending = { modelVersion: 1, state: 'unknown', amountMinor: '500000', identityHmac: 'opaque-intent' };
    const result = { modelVersion: 1, state: 'unacknowledged', eventId: 'opaque-result' };
    const fence = { modelVersion: 1, intentId: 'opaque-intent', stage: 'admitted' };
    await store.compareAndSet('payment', null, pending);
    await store.compareAndSet('result', null, result);
    await store.compareAndSet('request-key', null, fence);

    const sitePaymentKey: SiteAttestationKey = {
      provider: 'paystack', siteId: 'site_1', keyId: 'site_key_1', purpose: 'site-payment',
      material: new Uint8Array(32).fill(7), state: 'current',
    };
    const rawBody = new TextEncoder().encode(JSON.stringify({
      schemaVersion: '1.0', siteId: 'site_1', subject: { kind: 'member', id: 'member_7' }, requestKey: 'erase_0123456789',
    }));
    const accepted = await verifySiteAttestation({
      provider: 'paystack', method: 'POST', route: 'customers/erase', rawBody, nowMs: 120_000,
      headers: {
        'x-payment-site-id': 'site_1', 'x-payment-key-id': 'site_key_1', 'x-payment-timestamp': '120',
        'x-payment-nonce': 'erase_nonce_123456', 'x-payment-signature': '0'.repeat(64),
      },
      keys: [sitePaymentKey],
    });

    expect(accepted).toBeNull();
    expect(store.inspect('payment')?.value).toEqual(pending);
    expect(store.inspect('result')?.value).toEqual(result);
    expect(store.inspect('request-key')?.value).toEqual(fence);
  });
});
