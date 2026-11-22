import { isVerifiedPaymentResult, type VerifiedPaymentResult } from '../../src/domain/result.js';
import type { CheckoutBinding } from './checkout-bridge.js';

/** A site-owned relay key, separate from Paystack and plugin attestation secrets. */
export async function signRelayBody(body: string, secret: string): Promise<string> {
  if (!/^[a-f0-9]{64}$/u.test(secret)) throw new TypeError('INVALID_RELAY_SECRET');
  const bytes = new Uint8Array(secret.match(/../gu)!.map((v) => parseInt(v, 16)));
  const key = await crypto.subtle.importKey('raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body)));
  return Array.from(sig, (v) => v.toString(16).padStart(2, '0')).join('');
}

export interface RelayOptions {
  readonly merchantProfile: string;
  readonly formId: string;
  readonly formRevision: string;
  readonly secret: string;
  readonly binding: (intentId: string) => Promise<CheckoutBinding | null>;
  /** Site-owned invocation of Core's webhook route. */
  readonly deliver: (body: string, signature: string) => Promise<Response>;
  readonly acknowledge: (eventId: string) => Promise<boolean>;
}
/** Delivers at least once; any uncertain delivery or acknowledgement remains eligible for retry. */
export async function relayVerifiedResult(result: VerifiedPaymentResult, options: RelayOptions): Promise<'acknowledged' | 'retry' | 'rejected'> {
  if (!isVerifiedPaymentResult(result) || result.merchantProfile !== options.merchantProfile ||
    result.formId !== options.formId || result.formRevision !== options.formRevision) return 'rejected';
  try {
    const binding = await options.binding(result.intentId);
    const [whole, fraction] = result.amount.value.split('.');
    const amount = Number(whole) * 100 + Number(fraction);
    if (!binding || binding.intentId !== result.intentId || binding.environment !== result.environment ||
      binding.currency !== result.amount.currency || !Number.isSafeInteger(amount) || binding.amount !== amount) return 'rejected';
    const body = JSON.stringify({ type: 'charge.succeeded', id: result.eventId, orderDraftId: binding.orderDraftId,
      checkoutReference: result.intentId, paymentReference: result.providerReference, amount, currency: 'NGN' });
    const response = await options.deliver(body, await signRelayBody(body, options.secret));
    if (response.status !== 200) return 'retry';
    const value: unknown = await response.json();
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
      (value as Record<string, unknown>).received !== true || (value as Record<string, unknown>).skipped === true) return 'retry';
    return await options.acknowledge(result.eventId) ? 'acknowledged' : 'retry';
  } catch { return 'retry'; }
}
