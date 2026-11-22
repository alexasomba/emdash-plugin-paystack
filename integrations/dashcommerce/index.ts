/** Trusted, server-only companion to the registry-installed sandboxed Paystack plugin. */
import { createResultClient } from '../../examples/astro-site/result-consumer/client.js';
import { createCoreBindingStore, type BindingKV } from './binding-store.js';
import { createDashcommerceCheckoutBridge, type CheckoutBridgeOptions } from './checkout-bridge.js';
import { createDashcommercePaystackProvider } from './provider.js';
import { relayVerifiedResult } from './relay.js';

type ResultClientOptions = Parameters<typeof createResultClient>[0];
export interface DashcommerceIntegrationOptions {
  readonly checkout: Omit<CheckoutBridgeOptions, 'bind'>;
  readonly resultClient: ResultClientOptions;
  readonly bindings: BindingKV;
  readonly relaySecret: string;
  /** Invoke Core's webhook route in the trusted site runtime with the exact provided bytes. */
  readonly deliver: (body: string, signature: string) => Promise<Response>;
}
export function createDashcommerceIntegration(options: DashcommerceIntegrationOptions) {
  const relayBytes = /^[a-f0-9]{64}$/u.test(options.relaySecret)
    ? new Uint8Array(options.relaySecret.match(/../gu)!.map((byte) => parseInt(byte, 16))) : null;
  const sameKey = (other: Uint8Array) => relayBytes?.length === other.length && relayBytes.every((byte, i) => byte === other[i]);
  if (!relayBytes || sameKey(options.checkout.attestationKey) || sameKey(options.resultClient.key) ||
    options.checkout.siteId !== options.resultClient.siteId ||
    options.checkout.installedPluginId !== options.resultClient.installedPluginId) throw new TypeError('INVALID_DASHCOMMERCE_CONFIGURATION');
  const store = createCoreBindingStore(options.bindings);
  const bridge = createDashcommerceCheckoutBridge({ ...options.checkout, bind: store.bind });
  const client = createResultClient(options.resultClient);
  const provider = createDashcommercePaystackProvider({
    async initialize(input) {
      // Admission binds the configured consumer to the intent. Do not create
      // a charge unless that consumer can access the feed now.
      if (!await client.feed(1)) return { kind: 'unavailable' as const };
      return bridge.initialize(input);
    },
  }, options.relaySecret);
  return Object.freeze({
    provider,
    /** Call Core's registerPaymentProvider once in the same runtime as its route handlers. */
    register(registerPaymentProvider: (value: typeof provider) => void): void { registerPaymentProvider(provider); },
    /** Invoke periodically from a trusted site job. Never treat a failed item as handled. */
    async poll(limit = 50, cursor?: string): Promise<{ acknowledged: number; retry: number; rejected: number; nextCursor?: string } | null> {
      const feed = await client.feed(limit, cursor);
      if (!feed) return null;
      const count = { acknowledged: 0, retry: 0, rejected: 0 };
      for (const item of feed.items) {
        const outcome = await relayVerifiedResult(item, { merchantProfile: options.checkout.merchantProfile,
          formId: options.checkout.formId, formRevision: options.checkout.formRevision, secret: options.relaySecret,
          binding: store.get, deliver: options.deliver, acknowledge: client.acknowledge });
        count[outcome]++;
      }
      return { ...count, ...(feed.nextCursor ? { nextCursor: feed.nextCursor } : {}) };
    },
  });
}
