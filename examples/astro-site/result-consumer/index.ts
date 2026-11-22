import { canonicalJson } from '../../../src/domain/identity.js';
import { isVerifiedPaymentResult, type VerifiedPaymentResult } from '../../../src/domain/result.js';

/** All methods execute in one durable database transaction owned by the consuming site.
 * The event ID must have a unique constraint and a failed insert must roll back the payment effect.
 */
export interface ResultTransaction {
  get(eventId: string): Promise<{ readonly payloadHash: string } | null>;
  /** Resolve the server-owned order and apply its payment effect inside this transaction. */
  applyPayment(event: VerifiedPaymentResult): Promise<void>;
  insert(eventId: string, payloadHash: string): Promise<void>;
}
export interface ResultConsumerStore {
  transaction<T>(fn: (tx: ResultTransaction) => Promise<T>): Promise<T>;
}
export type ConsumeResult = 'acknowledged' | 'ack_pending' | 'invalid' | 'payload_conflict' | 'transaction_failed';

/**
 * Commit deduplication and the local business effect together before sending the
 * acknowledgement. A callback must resolve an existing site-owned order and
 * validate its frozen payment identity, amount, currency and environment.
 */
export async function consumeVerifiedResult(input: {
  readonly event: unknown;
  readonly consumerId: string;
  readonly store: ResultConsumerStore;
  readonly acknowledge: (value: { schemaVersion: '1.0'; consumerId: string; eventId: string; outcome: 'durably_handled' }) => Promise<boolean>;
}): Promise<ConsumeResult> {
  if (!isVerifiedPaymentResult(input.event) || !/^[A-Za-z0-9_-]{1,120}$/u.test(input.consumerId)) return 'invalid';
  const event = input.event;
  let hash: string;
  try {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalJson(event)));
    hash = Array.from(new Uint8Array(digest), (v) => v.toString(16).padStart(2, '0')).join('');
  } catch { return 'invalid'; }
  try {
    const state = await input.store.transaction(async (tx) => {
      const prior = await tx.get(event.eventId);
      if (prior) return prior.payloadHash === hash ? 'seen' : 'conflict';
      await tx.applyPayment(event);
      await tx.insert(event.eventId, hash);
      return 'applied';
    });
    if (state === 'conflict') return 'payload_conflict';
  } catch { return 'transaction_failed'; }
  try {
    return await input.acknowledge({ schemaVersion: '1.0', consumerId: input.consumerId, eventId: event.eventId,
      outcome: 'durably_handled' }) ? 'acknowledged' : 'ack_pending';
  } catch { return 'ack_pending'; }
}
