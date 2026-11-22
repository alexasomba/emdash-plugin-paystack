import { describe, expect, it } from 'vite-plus/test';
import { bindConfigurationBehavior } from '../support/configuration-binding.js';
import { expectBusinessOutcome } from '../support/behavior-assertions.js';
import { PaymentTestDriver } from '../support/driver.js';

describe('revisioned plugin configuration contract', () => {
  it('TC-CFG-001 starts paused with no live profile and health never initializes payment', async () => {
    const driver = new PaymentTestDriver();
    bindConfigurationBehavior(driver);
    await expectBusinessOutcome(driver, 'configuration.read', { action: 'read' }, {
      configured: false, paused: true, health: 'unconfigured', revision: null,
    });
    await expectBusinessOutcome(driver, 'configuration.health', { action: 'health' }, {
      configured: false, paused: true, health: 'unconfigured', revision: null,
    });
    expect(driver.network.transmissions).toBe(0);
  });

  it('TC-CFG-002 persists one encrypted JSON string, preserves absent secrets, and never echoes secrets', async () => {
    const driver = new PaymentTestDriver();
    bindConfigurationBehavior(driver);
    await expectBusinessOutcome(driver, 'configuration.save', {
      action: 'save', environment: 'test', merchantProfile: 'test-profile',
      credentials: { secretKey: 'sk_test_fixture-only-secret' }, expectedRevision: null,
    }, { environment: 'test', merchantProfile: 'test-profile', configured: true, paused: true, health: 'ready', revision: 'rev-1' });
  });

  it('TC-CFG-003 rejects stale save or pause without overwriting the newer revision', async () => {
    const driver = new PaymentTestDriver();
    bindConfigurationBehavior(driver);
    await expectBusinessOutcome(driver, 'configuration.save', {
      action: 'save', environment: 'test', merchantProfile: 'test-profile', expectedRevision: 'stale-rev',
    }, { ok: false, error: { code: 'stale_revision' } });
    await expectBusinessOutcome(driver, 'configuration.save', {
      action: 'pause', paused: false, expectedRevision: 'stale-rev',
    }, { ok: false, error: { code: 'stale_revision' } });
    expect(driver.network.transmissions).toBe(0);
  });
});
