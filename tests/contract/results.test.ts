import { describe, expect, it } from 'vite-plus/test';
import { createVerifiedPaymentResult } from '../../src/domain/result.js';
import { isConsistentPaidAggregate } from '../../src/domain/verification.js';
import { signInspectionCursor, verifyInspectionCursor } from '../../src/storage/cursors.js';
import { createIndexHmacKey } from '../../src/security/encryption.js';
import { consumeVerifiedResult, type ResultConsumerStore } from '../../examples/astro-site/result-consumer/index.js';

const intentId = `psk:v1:intents:${'a'.repeat(64)}`, attemptId = `psk:v1:attempts:${'b'.repeat(64)}`;
async function event() { return createVerifiedPaymentResult({ intentId, attemptId, formId: 'form', formRevision: '1',
  environment: 'test', merchantProfile: 'merchant', amount: { currency: 'NGN', value: '5000.00' },
  verifiedAt: '2026-10-18T00:00:00.000Z', providerResourceId: '123', providerReference: 'reference' }); }

describe('verified result feed and consumer acknowledgment contracts', () => {
  it('TC-RES-001 derives a stable event identity and refuses an inconsistent paid aggregate', async () => {
    const first = await event(), second = await event();
    expect(first.eventId).toBe(second.eventId);
    expect(first.paymentId).toBe(intentId);
    expect(isConsistentPaidAggregate({ state: 'verified_paid', resultEvent: first })).toBe(false);
    // The sandbox feed also rejects non-paid and inconsistent aggregate records; tests/host/results.test.ts exercises that boundary.
  });

  it('TC-RES-002 binds a pagination cursor to its site, consumer, filter and page size', async () => {
    const key = createIndexHmacKey('identity', new Uint8Array(32).fill(4));
    const keys = { activeKeyId: key.keyId, keys: [key] };
    const scope = { siteBinding: 'site/consumer', view: 'result-feed' as const, filter: null, sort: 'verifiedAt:asc' as const, limit: 50 };
    const cursor = await signInspectionCursor('opaque-host-page', scope, keys, 1000);
    expect(await verifyInspectionCursor(cursor, scope, keys, 1001)).toBe('opaque-host-page');
    expect(await verifyInspectionCursor(cursor, { ...scope, siteBinding: 'site/other' }, keys, 1001)).toBeNull();
    expect(await verifyInspectionCursor(cursor, { ...scope, limit: 49 }, keys, 1001)).toBeNull();
    // Concurrent insertion and paging against the actual host are covered by tests/host/results.test.ts.
  });

  it('TC-RES-003 rejects a conflicting payload and makes equal ACK replay idempotent', async () => {
    const item = await event(), rows = new Map<string, string>(); let effects = 0, acks = 0;
    const store: ResultConsumerStore = { transaction: async (fn) => fn({ get: async (id) => rows.has(id) ? { payloadHash: rows.get(id)! } : null,
      applyPayment: async () => { effects++; }, insert: async (id, hash) => { rows.set(id, hash); } }) };
    const acknowledge = async () => { acks++; return true; };
    expect(await consumeVerifiedResult({ event: item, consumerId: 'consumer', store, acknowledge })).toBe('acknowledged');
    expect(await consumeVerifiedResult({ event: item, consumerId: 'consumer', store, acknowledge })).toBe('acknowledged');
    expect(await consumeVerifiedResult({ event: { ...item, amount: { currency: 'NGN', value: '5001.00' } }, consumerId: 'consumer', store, acknowledge })).toBe('payload_conflict');
    expect(effects).toBe(1); expect(acks).toBe(2);
    // Wrong-site, wrong-consumer and wrong-event acknowledgement denial is covered by tests/host/results.test.ts.
  });
});
