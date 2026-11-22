import { afterEach, describe, expect, it } from 'vite-plus/test';
import { createPluginRuntimeTestHost, type PluginRuntimeTestHost } from '@emdash-cms/plugin-test';

const providerStage = [
  'settings.getVersioned',
  'storage.query:due',
  'storage.getVersioned:intent',
  'storage.compareAndSet:claim',
  'http.fetch:mocked-provider',
  'storage.compareAndSet:outcome',
  'storage.compareAndSet:inbox',
  'log.info',
] as const;

const admissionStage = [
  'settings.getVersioned',
  'storage.getVersioned:nonce',
  'storage.compareAndSet:nonce',
  'storage.getVersioned:quota',
  'storage.compareAndSet:quota-reservation',
  'storage.compareAndSet:quota-cooldown',
  'storage.getVersioned:claim',
  'storage.compareAndSet:claim',
] as const;

describe('T006 local runtime budget probe', () => {
  let host: PluginRuntimeTestHost | undefined;

  afterEach(async () => {
    await host?.dispose();
    host = undefined;
  });

  it('executes the admission operations as a bounded eight-call stage', async () => {
    host = await createPluginRuntimeTestHost();
    await host.fixtures.plugin.setting('probe-setting', 'local-fixture-value');

    const response = await host.actions.routes.request('probe/budget-admission', { method: 'POST', body: {} });
    const envelope = await response.json() as {
      success: boolean;
      data: { ok: boolean; value: { operations: string[]; nonceApplied: boolean; quotaApplied: boolean } };
    };

    expect(response.status).toBe(200);
    expect(envelope).toMatchObject({ success: true, data: { ok: true, value: { operations: admissionStage } } });
    expect(envelope.data.value.operations).toHaveLength(8);
    expect(envelope.data.value.nonceApplied).toBe(true);
    expect(envelope.data.value.quotaApplied).toBe(true);
    expect(host.http.requests()).toHaveLength(0);
  });

  it('executes the provider stage at eight operations with an intercepted local response', async () => {
    host = await createPluginRuntimeTestHost();
    await host.fixtures.plugin.setting('probe-setting', 'local-fixture-value');
    await host.http.respond('https://api.paystack.co/transaction/initialize', new Response('{"status":true}', {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }));

    const response = await host.actions.routes.request('probe/budget-provider', { method: 'POST', body: {} });
    const envelope = await response.json() as {
      success: boolean;
      data: { ok: boolean; value: { operations: string[]; mockedStatus: number | null } };
    };

    expect(response.status).toBe(200);
    expect(envelope.data.value.operations).toEqual(providerStage);
    expect(envelope.data.value.operations).toHaveLength(8);
    expect(envelope.data.value.mockedStatus).toBe(200);
    expect(host.http.requests()).toHaveLength(1);
    expect(host.http.requests()[0]?.url).toBe('https://api.paystack.co/transaction/initialize');
  });

  it('runs the 25-second cron handler through the local scheduled dispatcher', async () => {
    host = await createPluginRuntimeTestHost();
    expect(host.manifest.hooks).toContainEqual({ name: 'cron', timeout: 25000 });

    await host.actions.plugin.activate();
    host.scheduled.setTime(new Date(Date.now() + 5 * 60_000));
    const result = await host.scheduled.run();

    expect(result.processed).toBeGreaterThan(0);
    expect(await host.inspect.kv.get('probe:cron')).toMatchObject({ name: 'probe-tick' });
  });
});
