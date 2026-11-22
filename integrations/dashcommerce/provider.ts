import type { CoreCheckout, BridgeCheckoutResult } from './checkout-bridge.js';
import { signRelayBody } from './relay.js';

export interface ProviderCheckout extends CoreCheckout {
  billingAddress?: { line1?: string; city?: string; country?: string };
  shippingAddress?: { line1?: string; city?: string; country?: string };
}
const eventId = /^psk:v1:results:[a-f0-9]{64}$/u;
const intentId = /^psk:v1:intents:[a-f0-9]{64}$/u;
const draftId = /^[A-Za-z0-9_-]{1,120}$/u;
const reference = /^[A-Za-z0-9.=\-]{1,100}$/u;
function addressComplete(address: ProviderCheckout['billingAddress']): boolean {
  return Boolean(address?.line1?.trim() && address.city?.trim() && address.country?.trim());
}
/** Register this object with Core only in a trusted host. The relay key is not a Paystack key. */
export function createDashcommercePaystackProvider(bridge: { initialize(input: CoreCheckout): Promise<BridgeCheckoutResult> }, relaySecret?: string) {
  return {
    id: 'paystack', label: 'Paystack', capabilities: {},
		...(relaySecret ? { async getCredentials() { return /^[a-f0-9]{64}$/u.test(relaySecret) ?
			{ secretKey: 'host-managed-paystack', webhookSecret: relaySecret } : null; } } : {}),
    supportsCurrency: (currency: string) => currency.toUpperCase() === 'NGN',
    async initCheckout(_ctx: unknown, input: ProviderCheckout, _credentials: unknown) {
      // Core requires an address to build an order; do not take money when it cannot do so.
      if (!addressComplete(input.billingAddress) && !addressComplete(input.shippingAddress)) throw new Error('Paystack checkout requires a complete address');
      const result = await bridge.initialize(input);
      if (result.kind === 'unavailable') throw new Error('Paystack checkout unavailable');
      return result;
    },
    async verifyWebhook(input: { rawBody: string; signatureHeader: string; secret: string }) {
      try {
        if (!/^[a-f0-9]{64}$/u.test(input.signatureHeader)) return { ok: false, reason: 'invalid signature' };
        const expected = await signRelayBody(input.rawBody, input.secret);
        let diff = 0;
        for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ input.signatureHeader.charCodeAt(i);
        return diff === 0 ? { ok: true } : { ok: false, reason: 'invalid signature' };
      } catch { return { ok: false, reason: 'invalid configuration' }; }
    },
    parseWebhookEvent(rawBody: string) {
      let value: unknown;
      try { value = JSON.parse(rawBody); } catch { value = null; }
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        const v = value as Record<string, unknown>;
        if (Object.keys(v).sort().join(',') === 'amount,checkoutReference,currency,id,orderDraftId,paymentReference,type' &&
          v.type === 'charge.succeeded' && typeof v.id === 'string' && eventId.test(v.id) &&
          typeof v.orderDraftId === 'string' && draftId.test(v.orderDraftId) &&
          typeof v.checkoutReference === 'string' && intentId.test(v.checkoutReference) &&
          typeof v.paymentReference === 'string' && reference.test(v.paymentReference) &&
          typeof v.amount === 'number' && Number.isSafeInteger(v.amount) && v.amount >= 5000 && v.amount <= 100_000_000 && v.currency === 'NGN') {
          return { type: 'charge.succeeded' as const, providerId: 'paystack', providerEventId: v.id, orderDraftId: v.orderDraftId,
            checkoutReference: v.checkoutReference, paymentReference: v.paymentReference, amount: v.amount, currency: 'NGN',
            customer: { email: '' }, channel: 'Paystack', raw: value };
        }
      }
      return { type: 'unhandled' as const, providerEventType: 'invalid', raw: value };
    },
    async refund(_ctx: unknown, _input: unknown, _credentials: unknown): Promise<never> { throw new Error('Paystack refunds are not supported by this adapter'); },
    formatAmount(amount: number, currency: string) { return new Intl.NumberFormat('en-NG', { style: 'currency', currency }).format(amount / 100); },
  };
}
