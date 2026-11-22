import { describe, expect, it } from 'vite-plus/test';
import { consumeVerifiedResult, type ResultConsumerStore } from '../../examples/astro-site/result-consumer/index.js';
import { createVerifiedPaymentResult } from '../../src/domain/result.js';

async function event() {
  return createVerifiedPaymentResult({ intentId: `psk:v1:intents:${'a'.repeat(64)}`,
    attemptId: `psk:v1:attempts:${'b'.repeat(64)}`, formId: 'form', formRevision: '1', environment: 'test',
    merchantProfile: 'merchant', amount: { currency: 'NGN', value: '5000.00' }, verifiedAt: '2026-10-18T00:00:00.000Z',
    providerResourceId: '123', providerReference: 'reference' });
}
function fixture() {
  const ledger = new Map<string, string>(); let effects = 0;
  const store: ResultConsumerStore = { transaction: async (fn) => {
    const staged = new Map(ledger); let nextEffects = effects;
    const value = await fn({ get: async (id) => staged.has(id) ? { payloadHash: staged.get(id)! } : null,
      applyPayment: async () => { nextEffects += 1; }, insert: async (id, hash) => { staged.set(id, hash); } });
    ledger.clear(); for (const [id, hash] of staged) ledger.set(id, hash); effects = nextEffects; return value;
  } };
  return { store, effects: () => effects };
}
describe('verified result consumer', () => {
  it('commits the effect once and retries a lost acknowledgement', async () => {
    const f = fixture(), payment = await event(); let calls = 0;
    const input = { event: payment, consumerId: 'commerce', store: f.store, acknowledge: async () => ++calls > 1 };
    expect(await consumeVerifiedResult(input)).toBe('ack_pending');
    expect(await consumeVerifiedResult(input)).toBe('acknowledged');
    expect(f.effects()).toBe(1);
  });
  it('rejects a changed payload with the same event id before acknowledgement or effects', async () => {
    const f = fixture(), payment = await event(); let acks = 0;
    const acknowledge = async () => { acks++; return true; };
    await consumeVerifiedResult({ event: payment, consumerId: 'commerce', store: f.store, acknowledge });
    expect(await consumeVerifiedResult({ event: { ...payment, amount: { currency: 'NGN', value: '9000.00' } },
      consumerId: 'commerce', store: f.store, acknowledge })).toBe('payload_conflict');
    expect(f.effects()).toBe(1); expect(acks).toBe(1);
  });
  it('does not acknowledge if recording the event fails after the payment effect', async () => {
    let committed = 0, acks = 0;
    const store: ResultConsumerStore = { transaction: async (fn) => {
      let staged = 0;
      const result = await fn({ get: async () => null, applyPayment: async () => { staged++; },
        insert: async () => { throw new Error('unique index conflict'); } });
      committed += staged; return result;
    } };
    expect(await consumeVerifiedResult({ event: await event(), consumerId: 'commerce', store,
      acknowledge: async () => { acks++; return true; } })).toBe('transaction_failed');
    expect(committed).toBe(0); expect(acks).toBe(0);
  });
  it('does not acknowledge a failed transaction', async () => {
    let acks = 0;
    const store: ResultConsumerStore = { transaction: async () => { throw new Error('offline'); } };
    expect(await consumeVerifiedResult({ event: await event(), consumerId: 'commerce', store,
      acknowledge: async () => { acks++; return true; } })).toBe('transaction_failed');
    expect(acks).toBe(0);
  });
});
