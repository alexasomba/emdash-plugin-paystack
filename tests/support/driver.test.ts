import { describe, expect, it } from 'vite-plus/test';
import { approvedPrivacyFixtures, listFixtureContextNames, loadFixtureContext } from './contracts.js';
import {
  deferred,
  FakeClock,
  InjectedCrash,
  PaymentTestDriver,
} from './driver.js';

 describe('test support driver', () => {
  it('TC-DRV-001 counts bridge calls by kind and operation without storing payloads', async () => {
    const driver = new PaymentTestDriver();
    await driver.rpc('settings', 'settings.getVersioned', () => 'r1');
    await driver.storage.compareAndSet('aggregate:1', null, { state: 'created' });
    driver.network.enqueue({ status: 200, body: '{"status":true}' });
    await driver.network.fetch({ method: 'POST', url: 'https://api.paystack.co/transaction/initialize' });
    driver.ledger.record('cron', 'ctx.cron.schedule');
    driver.ledger.record('log', 'ctx.log.info');

    expect(driver.ledger.count()).toBe(5);
    expect(driver.ledger.count('storage')).toBe(1);
    expect(driver.ledger.count('http')).toBe(1);
    expect(driver.ledger.countOperation('ctx.http.fetch')).toBe(1);
    expect(driver.network.transmissions).toBe(1);
    expect(driver.network.requests[0]).toEqual({
      method: 'POST',
      url: 'https://api.paystack.co/transaction/initialize',
      headerNames: [],
    });
  });

  it('TC-DRV-002 preserves conditional writes across restart and models uncertain outcomes', async () => {
    const driver = new PaymentTestDriver();
    const first = await driver.storage.compareAndSet('intent:one', null, { state: 'created' });
    expect(first).toEqual({ kind: 'written', revision: 1 });

    driver.storage.injectNext('unknown-after-commit');
    expect(await driver.storage.compareAndSet('intent:one', 1, { state: 'pending' })).toEqual({ kind: 'unknown' });
    const restarted = driver.restart();
    expect(await restarted.storage.get('intent:one')).toEqual({ revision: 2, value: { state: 'pending' } });

    restarted.storage.injectNext('unknown-before-commit');
    expect(await restarted.storage.compareAndSet('intent:one', 2, { state: 'paid' })).toEqual({ kind: 'unknown' });
    expect(restarted.storage.inspect('intent:one')).toEqual({ revision: 2, value: { state: 'pending' } });

    restarted.storage.injectNext('crash-after-commit');
    await expect(restarted.storage.compareAndSet('intent:one', 2, { state: 'paid' })).rejects.toBeInstanceOf(InjectedCrash);
    expect(restarted.storage.inspect('intent:one')).toEqual({ revision: 3, value: { state: 'paid' } });
  });

  it('TC-DRV-003 lets a provider reply arrive after a local deadline without a second transmission', async () => {
    const driver = new PaymentTestDriver();
    const providerReply = deferred<{ status: number; body: string }>();
    const localDeadline = deferred<{ kind: 'deadline' }>();
    driver.network.enqueueDeferred(providerReply);

    const remoteRequest = driver.network.fetch({
      method: 'POST',
      url: 'https://api.paystack.co/transaction/initialize',
      body: '{"amount":250000,"currency":"NGN"}',
    });
    localDeadline.resolve({ kind: 'deadline' });
    expect(await Promise.race([remoteRequest, localDeadline.promise])).toEqual({ kind: 'deadline' });
    providerReply.resolve({ status: 200, body: '{"status":true}' });
    expect(await remoteRequest).toEqual({ status: 200, body: '{"status":true}' });
    expect(driver.network.transmissions).toBe(1);
    expect(driver.ledger.countOperation('ctx.http.fetch')).toBe(1);
  });

  it('TC-DRV-004 returns a typed unimplemented result instead of hiding missing behavior', async () => {
    const driver = new PaymentTestDriver();
    expect(await driver.invoke('payment.submit', { amount: '2500.00' })).toEqual({
      kind: 'unimplemented',
      code: 'UNIMPLEMENTED',
      operation: 'payment.submit',
    });
    driver.register('payment.submit', (input) => ({ accepted: input !== null }));
    expect(await driver.invoke('payment.submit', {})).toEqual({
      kind: 'implemented',
      value: { accepted: true },
    });
  });

  it('TC-DRV-005 freezes the approved fixture contexts and privacy examples', () => {
    expect(listFixtureContextNames()).toHaveLength(6);
    expect(loadFixtureContext('fixed_amount_override').form.pricing.mode).toBe('fixed');
    expect(loadFixtureContext('payer_entered_policy_override').form.pricing.mode).toBe('payer_entered');
    expect(Object.isFrozen(loadFixtureContext('fixed_amount_override').form)).toBe(true);
    expect(approvedPrivacyFixtures.maskingCases).toHaveLength(16);
    expect(approvedPrivacyFixtures.negativeCases.map(({ id }) => id)).toEqual([
      'reject-pii-and-payload-projection',
      'no-raw-error-or-nested-fallback',
      'feed-is-distinct',
    ]);
  });
});
