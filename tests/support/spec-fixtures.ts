import fixedForm from '../../features/paystack-payments/product-spec/examples/fixed-form-v1.json' with { type: 'json' };
import orderForm from '../../features/paystack-payments/product-spec/examples/order-form-v1.json' with { type: 'json' };
import payerEnteredForm from '../../features/paystack-payments/product-spec/examples/payer-entered-form-v1.json' with { type: 'json' };
import browserSubmission from '../../features/paystack-payments/product-spec/examples/browser-submission-v1.json' with { type: 'json' };
import trustedOrderRequest from '../../features/paystack-payments/product-spec/examples/trusted-order-request-v1.json' with { type: 'json' };
import trustedServerRequest from '../../features/paystack-payments/product-spec/examples/trusted-server-request-v1.json' with { type: 'json' };
import rejectedPricingOverrides from '../../features/paystack-payments/product-spec/examples/rejected-pricing-overrides-v1.json' with { type: 'json' };
import intentDeduplication from '../../features/paystack-payments/product-spec/examples/intent-deduplication-v1.json' with { type: 'json' };
import adminProjection from '../../features/paystack-payments/product-spec/examples/admin-projection-v1.json' with { type: 'json' };
import verifiedResult from '../../features/paystack-payments/product-spec/examples/verified-result-v1.json' with { type: 'json' };
import resultAck from '../../features/paystack-payments/product-spec/examples/result-ack-v1.json' with { type: 'json' };

export type DeepReadonly<T> = T extends (...args: never[]) => unknown
  ? T
  : T extends object
    ? { readonly [K in keyof T]: DeepReadonly<T[K]> }
    : T;

export function deepFreeze<T>(value: T): DeepReadonly<T> {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreeze(child);
    }
    Object.freeze(value);
  }
  return value as DeepReadonly<T>;
}

export const approvedExamples = deepFreeze({
  fixedForm,
  orderForm,
  payerEnteredForm,
  browserSubmission,
  trustedOrderRequest,
  trustedServerRequest,
  rejectedPricingOverrides,
  intentDeduplication,
  adminProjection,
  verifiedResult,
  resultAck,
});
