import { expect } from 'vite-plus/test';
import type { FeatureOperation, PaymentTestDriver } from './driver.js';

/** Assert the business result expected once the feature operation is implemented. */
export async function expectBusinessOutcome(
  driver: PaymentTestDriver,
  operation: FeatureOperation,
  input: unknown,
  expectedValue: unknown,
  sideEffects: { readonly providerTransmissions?: number; readonly httpBridgeCalls?: number; readonly maximumRpcCalls?: number } = {},
): Promise<void> {
  const result = await driver.invoke(operation, input);
  expect.soft(result).toEqual({
    kind: 'implemented',
    value: expectedValue,
  });
  expect.soft(driver.network.transmissions).toBe(sideEffects.providerTransmissions ?? 0);
  expect.soft(driver.ledger.count('http')).toBe(sideEffects.httpBridgeCalls ?? 0);
  if (sideEffects.maximumRpcCalls !== undefined) {
    expect.soft(driver.ledger.count()).toBeLessThanOrEqual(sideEffects.maximumRpcCalls);
  }
}
