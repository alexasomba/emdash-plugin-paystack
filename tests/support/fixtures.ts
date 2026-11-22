import type { PaymentTestDriver } from './driver.js';

export interface FixtureContext {
  readonly name: string;
  readonly siteId: string;
  readonly subject: { readonly kind: 'guest' | 'member'; readonly id: string };
  readonly merchantProfile: string;
  readonly environment: 'test';
}

export function createFixtureContext(name: string): FixtureContext {
  return Object.freeze({
    name,
    siteId: 'site_verified_001',
    subject: Object.freeze({ kind: 'guest', id: 'site_verified_guest_001' }),
    merchantProfile: 'configured_test_profile',
    environment: 'test',
  });
}

export interface DriverFixture {
  readonly driver: PaymentTestDriver;
  readonly context: FixtureContext;
}

export function createDriverFixture(name: string, driver: PaymentTestDriver): DriverFixture {
  return Object.freeze({ driver, context: createFixtureContext(name) });
}
