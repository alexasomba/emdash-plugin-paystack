import type { CheckoutBinding } from './checkout-bridge.js';

/** Core-owned, versioned KV only; never use a process-local map for payment bindings. */
export interface BindingKV {
  getVersioned(key: string): Promise<{ value: unknown; revision: string } | null>;
  compareAndSet(key: string, revision: string | null, value: unknown): Promise<{ applied: boolean }>;
}
const INTENT = /^psk:v1:intents:[a-f0-9]{64}$/u;
const DRAFT = /^[A-Za-z0-9_-]{1,120}$/u;
function valid(value: unknown): value is CheckoutBinding {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  return Object.keys(v).sort().join(',') === 'amount,currency,environment,intentId,orderDraftId' &&
    typeof v.intentId === 'string' && INTENT.test(v.intentId) && typeof v.orderDraftId === 'string' && DRAFT.test(v.orderDraftId) &&
    typeof v.amount === 'number' && Number.isSafeInteger(v.amount) && v.amount >= 5000 && v.amount <= 100_000_000 &&
    v.currency === 'NGN' && (v.environment === 'test' || v.environment === 'live');
}
function equal(a: CheckoutBinding, b: CheckoutBinding): boolean {
  return a.intentId === b.intentId && a.orderDraftId === b.orderDraftId && a.amount === b.amount &&
    a.currency === b.currency && a.environment === b.environment;
}
function storageKey(intentId: string): string { return `paystack-intent-binding:${intentId}`; }
export function createCoreBindingStore(kv: BindingKV) {
  return Object.freeze({
    async get(intentId: string): Promise<CheckoutBinding | null> {
      if (!INTENT.test(intentId)) return null;
      try { const row = await kv.getVersioned(storageKey(intentId)); return row && valid(row.value) && row.value.intentId === intentId ? row.value : null; }
      catch { return null; }
    },
    async bind(value: CheckoutBinding): Promise<boolean> {
      if (!valid(value)) return false;
      const key = storageKey(value.intentId);
      try {
        const current = await kv.getVersioned(key);
        if (current) return valid(current.value) && equal(current.value, value);
        const created = await kv.compareAndSet(key, null, value);
        if (created.applied) return true;
      } catch { /* Read back once: a rejected write may already have committed. */ }
      try {
        const observed = await kv.getVersioned(key);
        return Boolean(observed && valid(observed.value) && equal(observed.value, value));
      } catch { return false; }
    },
  });
}
