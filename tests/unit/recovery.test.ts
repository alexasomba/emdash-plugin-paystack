import { describe, expect, it } from 'vitest';
import { createFixture, invoke, makeTrustedBody } from '../support/site-admission-fixture.js';
import { PAYMENT_CONFIGURATION_SETTING, parseStoredPaymentConfiguration } from '../../src/domain/configuration.js';
import { PAYSTACK_RETRY_FINALITY_POLICY, planPaymentRetry } from '../../src/domain/retry.js';
import { createIndexHmacKey, decodeBase64Url, hmacIndex } from '../../src/security/encryption.js';
import { claimSchedulerHealth, finishSchedulerHealth, SCHEDULER_LEASE_MS } from '../../src/storage/scheduler-health.js';
import type { ModelRecord } from '../../src/storage/schema.js';
import { createPaystackReference } from '../../src/provider/paystack-reference.js';

describe('durable reconciliation and recovery contracts', () => {
  it('TC-REC-001 uses expiring fenced leases and moves CAS conflicts to at most three fresh invocations', async () => {
    const fixture = await createFixture();
    const store = fixture.budgets;
    const first = await claimSchedulerHealth(store, 'a'.repeat(32), 1_000);
    expect(first.kind).toBe('claimed');
    if (first.kind !== 'claimed') throw new Error('initial lease was not acquired');
    expect(first.lease.expiresAt).toBe(1_000 + SCHEDULER_LEASE_MS);
    expect((await claimSchedulerHealth(store, 'b'.repeat(32), first.lease.expiresAt - 1)).kind).toBe('busy');
    const second = await claimSchedulerHealth(store, 'b'.repeat(32), first.lease.expiresAt);
    expect(second.kind).toBe('claimed');
    if (second.kind !== 'claimed') throw new Error('expired lease was not replaced');
    expect(second.lease.epoch).toBe(first.lease.epoch + 1);
    expect(await finishSchedulerHealth(store, first, {
      nowMs: first.lease.expiresAt, scanSucceeded: true, oldestDueAt: null,
    })).toBe(false);

    // Conflicts require a fresh invocation. Each attempt issues only one conditional write.
    const writes = store.compareAndSetCalls;
    for (let invocation = 0; invocation < 3; invocation++) {
      store.conflictNextCas();
      const result = await claimSchedulerHealth(store, 'c'.repeat(32), second.lease.expiresAt + invocation);
      expect(result.kind).toBe('unavailable');
    }
    expect(store.compareAndSetCalls - writes).toBe(3);
    const stored = store.values()[0] as ModelRecord;
    expect(stored.leaseEpoch).toBe(second.lease.epoch);
    expect(stored.lastSuccessfulAt).toBe(120_000);
  });

  it('TC-REC-002 permits a successor only after verified-final failure, never timeout, abandoned, unknown, or pending', async () => {
    const fixture = await createFixture();
    const body = makeTrustedBody();
    await invoke(fixture.dependencies, body, 'contract_retry_admission_1');
    await invoke(fixture.dependencies, body, 'contract_retry_middle_1');
    await invoke(fixture.dependencies, body, 'contract_retry_allocation_1');
    const intent = fixture.intents.values()[0]!;
    const predecessor = intent.attempts[0]!;
    const now = fixture.dependencies.now!();
    const setting = await fixture.dependencies.settings.getVersioned<string>(PAYMENT_CONFIGURATION_SETTING);
    const configuration = parseStoredPaymentConfiguration(JSON.parse(setting!.value))!;
    const storedKey = configuration.identityHmacKeyRing.keys[0]!;
    const key = createIndexHmacKey(storedKey.keyId, decodeBase64Url(storedKey.material));
    const providerReference = createPaystackReference(intent.identityHmac, 1)!;
    const verifiedAt = new Date(now).toISOString();
    const profileBinding = await hmacIndex([
      'paystack-finality-profile-v1', intent.identityHmac, intent.merchantProfile, intent.environment,
      String(predecessor.credentialVersion), PAYSTACK_RETRY_FINALITY_POLICY,
    ], key);
    const proofBinding = await hmacIndex([
      'paystack-finality-proof-v1', profileBinding, predecessor.id, providerReference, verifiedAt, 'failed',
    ], key);
    // This is fixture evidence for the retry policy. The real provider verifier has to establish finality.
    const finalityEvidence = {
      modelVersion: 1, policyVersion: PAYSTACK_RETRY_FINALITY_POLICY, provider: 'paystack',
      profileId: intent.merchantProfile, environment: intent.environment, credentialVersion: predecessor.credentialVersion,
      attemptId: predecessor.id, providerReference, status: 'failed', verifiedAt, profileBinding, proofBinding,
    };
    const failedAttempt = {
      ...predecessor, state: 'verified_failed', providerState: 'failed',
      createTransmissionStarted: true, providerReference, finalityEvidence,
    };
    const candidate = (state: string, providerState: string, evidence: unknown) => ({
      ...intent, state, attempts: [{ ...failedAttempt, state, providerState, finalityEvidence: evidence }],
    });
    const plan = (record: unknown, at = now, fingerprint = intent.fingerprintHmac) =>
      planPaymentRetry(record, predecessor.id, fingerprint, key, at);
    const proved = candidate('verified_failed', 'failed', finalityEvidence);
    expect(await plan(proved)).toMatchObject({ kind: 'eligible', successorOrdinal: 2 });
    expect(await plan(candidate('verified_failed', 'failed', null))).toEqual({ kind: 'not_allowed' });
    expect(await plan(candidate('verified_failed', 'failed', { ...finalityEvidence, proofBinding: 'a'.repeat(64) })))
      .toEqual({ kind: 'not_allowed' });
    expect(await plan(proved, now + 300_001)).toEqual({ kind: 'not_allowed' });
    expect(await plan(proved, now, 'f'.repeat(64))).toEqual({ kind: 'not_allowed' });
    for (const observed of ['failed', 'timeout', 'abandoned', 'unknown', 'pending']) {
      expect(await plan(candidate('unknown', observed, finalityEvidence))).toEqual({ kind: 'not_allowed' });
    }
  });

});
