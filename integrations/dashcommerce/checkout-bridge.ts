/** Trusted server-only bridge from one DashCommerce draft to the sandboxed Paystack plugin. */
import { canonicalAttestationFrame } from '../../src/security/attestation.js';
import { encodeBase64Url, toHex } from '../../src/security/encryption.js';
import { fromRawHostExecution } from '../../src/routes/response.js';
import { isPlainObject } from '../../src/storage/schema.js';

export interface CoreCheckout {
  readonly orderDraftId: string;
  readonly amount: number;
  readonly currency: string;
  readonly customer: { readonly email: string };
  readonly successUrl: string;
  readonly mode?: 'payment' | 'subscription';
  readonly automaticTax?: boolean;
  readonly discounts?: readonly unknown[];
  readonly transferData?: unknown;
  readonly applicationFeeAmount?: number;
}
export interface CheckoutBinding {
  readonly intentId: string;
  readonly orderDraftId: string;
  readonly amount: number;
  readonly currency: 'NGN';
  readonly environment: 'test' | 'live';
}
export interface CheckoutBridgeOptions {
  readonly installedPluginId: string;
  readonly siteId: string;
  readonly keyId: string;
  readonly attestationKey: Uint8Array;
  readonly merchantProfile: string;
  readonly environment: 'test' | 'live';
  readonly formId: string;
  readonly formRevision: string;
  readonly siteOrigin: string;
  /** Durable atomic insert-or-equal mapping; conflict or uncertain write must return false. */
  readonly bind: (binding: CheckoutBinding) => Promise<boolean>;
  readonly invoke?: (pluginId: string, path: string, request: Request) => Promise<unknown>;
  readonly now?: () => number;
}
export type BridgeCheckoutResult =
  | { readonly kind: 'redirect'; readonly checkoutReference: string; readonly redirectUrl: string }
  | { readonly kind: 'pending'; readonly checkoutReference: string }
  | { readonly kind: 'unavailable' };
const ID = /^[A-Za-z0-9_-]{1,120}$/u;
const INTENT = /^psk:v1:intents:[a-f0-9]{64}$/u;
const ATTEMPT = /^psk:v1:attempts:[a-f0-9]{64}$/u;

export function createDashcommerceCheckoutBridge(options: CheckoutBridgeOptions) {
  const invoke = options.invoke ?? (async (pluginId, path, request) => {
    const { withEmDashRuntime } = await import('emdash/middleware');
    return withEmDashRuntime((runtime) => runtime.handlePluginApiRoute(pluginId, 'POST', `/${path}`, request));
  });
  async function call(route: 'payments/submit' | 'payments/action', value: object): Promise<unknown> {
    try {
      const now = options.now?.() ?? Date.now();
      if (!Number.isSafeInteger(now) || now < 0) return null;
      const bytes = new TextEncoder().encode(JSON.stringify(value));
      const nonce = encodeBase64Url(crypto.getRandomValues(new Uint8Array(24)));
      const digest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
      const timestampSeconds = Math.floor(now / 1000);
      const frame = canonicalAttestationFrame({ siteId: options.siteId, keyId: options.keyId, timestampSeconds,
        nonce, method: 'POST', route, bodyDigest: digest });
      const key = await crypto.subtle.importKey('raw', options.attestationKey.slice().buffer,
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      const signature = toHex(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(frame))));
      const request = new Request(`https://emdash.internal/${route}`, { method: 'POST', body: bytes, headers: {
        'content-type': 'application/json', 'x-payment-site-id': options.siteId, 'x-payment-key-id': options.keyId,
        'x-payment-timestamp': String(timestampSeconds), 'x-payment-nonce': nonce, 'x-payment-signature': signature,
      } });
      const result = fromRawHostExecution(await invoke(options.installedPluginId, route, request));
      return result.ok ? result.value : null;
    } catch { return null; }
  }
  return Object.freeze({
    async initialize(input: CoreCheckout): Promise<BridgeCheckoutResult> {
      try {
        const origin = new URL(options.siteOrigin), callback = new URL(input.successUrl);
        if (!ID.test(options.siteId) || !ID.test(options.keyId) || !ID.test(options.merchantProfile) ||
          !ID.test(options.formId) || !ID.test(options.formRevision) || !ID.test(input.orderDraftId) ||
          !options.installedPluginId || options.attestationKey.byteLength !== 32 ||
          (options.environment !== 'test' && options.environment !== 'live') || origin.protocol !== 'https:' ||
          origin.origin !== options.siteOrigin || callback.origin !== origin.origin || callback.username || callback.password ||
          input.currency.toUpperCase() !== 'NGN' || !Number.isSafeInteger(input.amount) || input.amount < 5000 || input.amount > 100_000_000 ||
          !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(input.customer.email) || input.mode === 'subscription' ||
          input.automaticTax || (input.discounts && input.discounts.length > 0) || input.transferData || input.applicationFeeAmount !== undefined) {
          return { kind: 'unavailable' };
        }
        // Core's Stripe placeholder is not meaningful to Paystack; its callback policy forbids queries.
        if (callback.hash || (callback.search && (callback.searchParams.size !== 1 ||
          callback.searchParams.get('session_id') !== '{CHECKOUT_SESSION_ID}'))) return { kind: 'unavailable' };
        callback.search = '';
        const submit = { schemaVersion: '1.0', siteId: options.siteId,
          subject: { kind: 'guest', id: input.orderDraftId }, businessReference: input.orderDraftId,
          merchantProfile: options.merchantProfile, expectedEnvironment: options.environment, resolvedOrderPrice: { currency: 'NGN', value: (input.amount / 100).toFixed(2) },
          submission: { schemaVersion: '1.0', formId: options.formId, formRevision: options.formRevision,
            requestKey: input.orderDraftId, fields: { payer_email: input.customer.email } } };
        let result: unknown = await call('payments/submit', submit);
        if (!isPlainObject(result) || typeof result.intentId !== 'string' || !INTENT.test(result.intentId)) return { kind: 'unavailable' };
        const intentId = result.intentId;
        if (!await options.bind({ intentId, orderDraftId: input.orderDraftId, amount: input.amount, currency: 'NGN', environment: options.environment })) {
          return { kind: 'unavailable' };
        }
        for (let retry = 0; retry < 2 && isPlainObject(result) && result.intentId === intentId && result.state === 'initializing'; retry++) {
          result = await call('payments/submit', submit);
        }
        if (!isPlainObject(result) || result.intentId !== intentId) return { kind: 'pending', checkoutReference: intentId };
        if (result.state !== 'created' && result.state !== 'requires_action') return { kind: 'pending', checkoutReference: intentId };
        if (typeof result.attemptId !== 'string' || !ATTEMPT.test(result.attemptId)) return { kind: 'unavailable' };
        const attemptId = result.attemptId;
        const action = await call('payments/action', { schemaVersion: '1.0', siteId: options.siteId,
          subject: { kind: 'guest', id: input.orderDraftId }, merchantProfile: options.merchantProfile,
          intentId, attemptId, actionId: attemptId, siteOrigin: origin.origin, callbackUrl: callback.href, expectedEnvironment: options.environment });
        if (!isPlainObject(action) || action.intentId !== intentId || action.attemptId !== attemptId) return { kind: 'pending', checkoutReference: intentId };
        if (action.state !== 'requires_action' || !isPlainObject(action.nextAction) || action.nextAction.id !== attemptId ||
          action.nextAction.kind !== 'redirect' || typeof action.nextAction.destination !== 'string') return { kind: 'pending', checkoutReference: intentId };
        const url = new URL(action.nextAction.destination);
        if (url.protocol !== 'https:' || url.hostname !== 'checkout.paystack.com' || url.port || url.username || url.password) return { kind: 'unavailable' };
        return { kind: 'redirect', checkoutReference: intentId, redirectUrl: url.href };
      } catch { return { kind: 'unavailable' }; }
    },
  });
}
