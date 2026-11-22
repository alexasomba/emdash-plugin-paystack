import { afterEach, beforeEach, describe, expect, it } from 'vite-plus/test';
import { createPluginRuntimeTestHost, type PluginRuntimeTestHost } from '@emdash-cms/plugin-test';

/** Fixed paths exercised by the disposable host fixture; never build a generic route proxy. */
export const HOST_BOUNDARY_ROUTES = Object.freeze({
  normal: 'probe/normal',
  bytes: 'probe/bytes',
  private: 'probe/private',
  rawAck: 'probe/raw-ack',
} as const);

let host: PluginRuntimeTestHost;

describe('EmDash 1.3 real-host boundary', () => {
  beforeEach(async () => {
    host = await createPluginRuntimeTestHost();
  });

  afterEach(async () => {
    await host?.dispose();
  });

  it('loads the fixed test plugin and uses only literal declared paths', () => {
    const declared = new Set(host.manifest.routes.map((route) => typeof route === 'string' ? route : route.name));
    expect(host.manifest.id).toBe('paystack-host-probe');
    expect([...Object.values(HOST_BOUNDARY_ROUTES)].every((route) => declared.has(route))).toBe(true);
  });

  it('preserves the JSON execution envelope at the actual host route dispatcher', async () => {
    const response = await host.actions.routes.request(HOST_BOUNDARY_ROUTES.normal, {
      method: 'POST',
      body: { probe: 'normal' },
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ success: true, data: { ok: true, value: { probe: 'normal' } } });
  });

  it('delivers original bytes and only declared signature headers to the route', async () => {
    const original = new Uint8Array([0x7b, 0x22, 0xff, 0x7d]);
    const response = await host.actions.routes.request(HOST_BOUNDARY_ROUTES.bytes, {
      method: 'POST',
      headers: { 'x-paystack-signature': 'fixture-signature', 'x-unlisted-probe': 'must-not-cross' },
      rawBody: original,
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      success: true,
      data: { ok: true, value: { bytes: [0x7b, 0x22, 0xff, 0x7d], signature: 'fixture-signature', unlisted: null } },
    });
  });

  it('enforces host authentication, RBAC, and mutation CSRF on private routes', async () => {
    const anonymous = await host.actions.routes.request(HOST_BOUNDARY_ROUTES.private, { method: 'POST', body: {} });
    expect(anonymous.status).toBe(401);

    const subscriber = await host.fixtures.user({ email: 'subscriber@example.test', role: 'subscriber' });
    const denied = await host.actions.routes.request(HOST_BOUNDARY_ROUTES.private, {
      method: 'POST', body: {}, user: subscriber,
    });
    expect(denied.status).toBe(403);

    const admin = await host.fixtures.user({ email: 'admin@example.test', role: 'admin' });
    const csrfDenied = await host.actions.routes.request(HOST_BOUNDARY_ROUTES.private, {
      method: 'POST', body: {}, user: admin,
    });
    expect(csrfDenied.status).toBe(403);

    const allowed = await host.actions.routes.request(HOST_BOUNDARY_ROUTES.private, {
      method: 'POST', headers: { 'x-emdash-request': '1' }, body: {}, user: admin,
    });
    expect(allowed.status).toBe(200);
  });

  it('returns the raw webhook acknowledgment status and body without a JSON envelope', async () => {
    const response = await host.actions.routes.request(HOST_BOUNDARY_ROUTES.rawAck, {
      method: 'POST',
      headers: { 'x-paystack-signature': 'fixture-signature' },
      rawBody: new Uint8Array([0x7b, 0x7d]),
    });

    expect(response.status).toBe(202);
    expect(response.headers.get('content-type')).toContain('text/plain');
    expect(await response.text()).toBe('accepted');
  });

  it('runs the supported scheduled dispatcher and retains its local result across restart', async () => {
    await host.actions.plugin.activate();
    expect((await host.inspect.scheduledTasks()).some((task) => task.name === 'probe-tick')).toBe(true);

    host.scheduled.setTime(new Date(Date.now() + 5 * 60_000));
    const run = await host.scheduled.run();
    expect(run.processed).toBeGreaterThan(0);
    expect(await host.inspect.kv.get('probe:cron')).toMatchObject({ name: 'probe-tick' });

    await host.restart();
    expect(await host.inspect.kv.get('probe:cron')).toMatchObject({ name: 'probe-tick' });
  });
});
