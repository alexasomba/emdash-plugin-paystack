import { describe, expect, it } from 'vite-plus/test';
import { createCoreBindingStore, type BindingKV } from '../../integrations/dashcommerce/binding-store.js';
const intentId = `psk:v1:intents:${'a'.repeat(64)}`;
const binding = { intentId, orderDraftId: 'draft_1', amount: 500_000, currency: 'NGN' as const, environment: 'test' as const };
function fixture() {
  const rows = new Map<string, unknown>(); let failAfterWrite = false;
  const kv: BindingKV = {
    getVersioned: async (key) => rows.has(key) ? { value: rows.get(key), revision: '1' } : null,
    compareAndSet: async (key, revision, value) => {
      if (revision !== null || rows.has(key)) return { applied: false };
      rows.set(key, value);
      if (failAfterWrite) { failAfterWrite = false; throw new Error('lost response'); }
      return { applied: true };
    },
  };
  return { store: createCoreBindingStore(kv), failNext: () => { failAfterWrite = true; } };
}
describe('Core checkout intent binding', () => {
  it('converges concurrent identical requests and refuses conflicting order or amount', async () => {
    const f = fixture();
    expect(await Promise.all([f.store.bind(binding), f.store.bind(binding)])).toEqual([true, true]);
    expect(await f.store.bind({ ...binding, orderDraftId: 'other' })).toBe(false);
    expect(await f.store.bind({ ...binding, amount: 600_000 })).toBe(false);
    expect(await f.store.get(intentId)).toEqual(binding);
  });
  it('reads back a committed binding when the write response is lost', async () => {
    const f = fixture(); f.failNext();
    expect(await f.store.bind(binding)).toBe(true);
    expect(await f.store.get(intentId)).toEqual(binding);
  });
});
