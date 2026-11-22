import { approvedExamples, deepFreeze } from './spec-fixtures.js';

export type FixtureContextName =
  | 'fixed_amount_override'
  | 'fixed_payer_amount'
  | 'order_payer_amount'
  | 'order_browser_resolved_price'
  | 'payer_entered_currency_override'
  | 'payer_entered_policy_override';

const formContextByName = {
  fixed_amount_override: {
    form: approvedExamples.fixedForm,
    expected: { code: 'protected_field_override', providerIoCalls: 0, providerCreations: 0 },
  },
  fixed_payer_amount: {
    form: approvedExamples.fixedForm,
    expected: { code: 'protected_field_override', providerIoCalls: 0, providerCreations: 0 },
  },
  order_payer_amount: {
    form: approvedExamples.orderForm,
    expected: { code: 'protected_field_override', providerIoCalls: 0, providerCreations: 0 },
  },
  order_browser_resolved_price: {
    form: approvedExamples.orderForm,
    expected: { code: 'protected_field_override', providerIoCalls: 0, providerCreations: 0 },
  },
  payer_entered_currency_override: {
    form: approvedExamples.payerEnteredForm,
    expected: { code: 'protected_field_override', providerIoCalls: 0, providerCreations: 0 },
  },
  payer_entered_policy_override: {
    form: approvedExamples.payerEnteredForm,
    expected: { code: 'protected_field_override', providerIoCalls: 0, providerCreations: 0 },
  },
} as const;

const contexts = deepFreeze(formContextByName);

export function loadFixtureContext(name: FixtureContextName) {
  return contexts[name];
}

export function listFixtureContextNames(): readonly FixtureContextName[] {
  return Object.freeze(Object.keys(contexts) as FixtureContextName[]);
}

export const approvedPrivacyFixtures = deepFreeze({
  acceptedProjections: approvedExamples.adminProjection.acceptedProjections,
  maskingCases: approvedExamples.adminProjection.maskingCases,
  negativeCases: approvedExamples.adminProjection.negativeCases,
});
