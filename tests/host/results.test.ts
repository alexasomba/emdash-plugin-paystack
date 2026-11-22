import { createResultClient } from '../../examples/astro-site/result-consumer/client.js';
import { afterEach, beforeEach, describe, expect, it } from 'vite-plus/test';
import { createPluginRuntimeTestHost, type PluginRuntimeTestHost } from '@emdash-cms/plugin-test';
import { canonicalAttestationFrame } from '../../src/security/attestation.js';
import { encodeBase64Url } from '../../src/security/encryption.js';
import { createVerifiedPaymentResult } from '../../src/domain/result.js';

let host: PluginRuntimeTestHost;
let admin: Awaited<ReturnType<PluginRuntimeTestHost['fixtures']['user']>>;
const key = new Uint8Array(32).fill(3);
const enc = (n: number) => encodeBase64Url(new Uint8Array(32).fill(n));
const site = 'site_1', consumer = 'consumer_1', profile = 'merchant_1';
const at = '2026-10-18T00:00:00.000Z';
let nonceCounter = 0;

describe('private Paystack result feed in EmDash runtime', () => {
  beforeEach(async () => {
    host = await createPluginRuntimeTestHost();
    admin = await host.fixtures.user({ email: 'results-admin@example.test', role: 'admin' });
    await host.fixtures.plugin.setting('paymentConfiguration', JSON.stringify({ schemaVersion: 1, paused: true,
      activeProfile: null, profiles: {}, integrationKeys: [
        { siteId: site, keyId: 'consumer_key', purpose: 'result-consumer', consumerId: consumer, secretBase64url: encodeBase64Url(key) },
      ], fieldEncryptionKeyRing: { activeKeyId: 'field', keys: [{ keyId: 'field', material: enc(4) }] },
      identityHmacKeyRing: { activeKeyId: 'identity', keys: [{ keyId: 'identity', material: enc(5) }] },
    }));
  });
  afterEach(async () => { await host?.dispose(); });

  it('reads and acknowledges a verified result through the site consumer client', async () => {
    const event = await seedPaid('9', site, consumer);
    const client = createResultClient({
      installedPluginId: host.manifest.id, siteId: site, consumerId: consumer,
      keyId: 'consumer_key', key, consumeQuota: async () => true,
      invoke: async (_pluginId, route, request) => {
        const response = await host.actions.routes.request(route, {
          method: 'POST', user: admin,
          headers: { ...Object.fromEntries(request.headers), 'x-emdash-request': '1' },
          rawBody: new Uint8Array(await request.arrayBuffer()),
        });
        return response.json();
      },
    });
    expect(await client.feed()).toMatchObject({items:[{eventId:event.eventId}]});
    expect(await client.acknowledge(event.eventId)).toBe(true);
    expect(await client.feed()).toEqual({items:[]});
  });

  it('keeps an event reachable after a concurrent insertion before the next poll', async () => {
    await seedPaid('3', site, consumer);
    await seedPaid('4', site, consumer);
    const first = await invoke('results/feed', { consumerId: consumer, limit: 1 }) as any;
    const inserted = await seedPaid('5', site, consumer);
    const observed = new Set<string>(first.value.items.map((item: { eventId: string }) => item.eventId));
    let cursor = first.value.nextCursor;
    for (let step = 0; cursor && step < 5; step++) {
      const page = await invoke('results/feed', { consumerId: consumer, limit: 1, cursor }) as any;
      expect(page.ok).toBe(true);
      for (const item of page.value.items) observed.add(item.eventId);
      cursor = page.value.nextCursor;
    }
    // A fresh poll is required after draining; pending results are not a watermark queue.
    const again = await invoke('results/feed', { consumerId: consumer, limit: 50 }) as any;
    for (const item of again.value.items) observed.add(item.eventId);
    expect(observed.has(inserted.eventId)).toBe(true);
    expect(observed.size).toBe(3);
  });

  it('preserves pending delivery across restart and refuses cross-scope acknowledgement', async () => {
    const event = await seedPaid('1', site, consumer);
    const other = await seedPaid('2', 'other_site', consumer);
    const ack = { schemaVersion: '1.0', consumerId: consumer, eventId: other.eventId, outcome: 'durably_handled' };
    expect(await invoke('results/ack', ack)).toMatchObject({ ok: false, error: { code: 'forbidden' } });
    await host.restart();
    const read = await invoke('results/feed', { consumerId: consumer });
    expect(read).toMatchObject({ ok: true, value: { items: [{ eventId: event.eventId }] } });
    expect(await host.inspect.storage.get<Record<string, unknown>>('intents', other.intentId)).toMatchObject({ deliveryState: 'pending' });
  });

  it('paginates without skipping a pending event when an earlier event is acknowledged', async () => {
    await seedPaid('d', site, consumer);
    await seedPaid('e', site, consumer);
    await seedPaid('f', site, consumer);
    const first = await invoke('results/feed', { consumerId: consumer, limit: 1 }) as any;
    expect(first.ok).toBe(true);
    expect(first.value.items).toHaveLength(1);
    expect(first.value.nextCursor).toBeTruthy();
    const initial = first.value.items[0];
    await invoke('results/ack', { schemaVersion: '1.0', consumerId: consumer, eventId: initial.eventId, outcome: 'durably_handled' });
    const second = await invoke('results/feed', { consumerId: consumer, limit: 1, cursor: first.value.nextCursor }) as any;
    expect(second.ok).toBe(true);
    expect(second.value.items).toHaveLength(1);
    expect(second.value.items[0].eventId).not.toBe(initial.eventId);
    expect(second.value.nextCursor).toBeTruthy();
  });

  it('repeats only bound pending events, acknowledges atomically and permits equal ack replay', async () => {
    const event = await seedPaid('a', site, consumer);
    await seedPaid('b', 'other_site', consumer);
    await seedPaid('c', site, 'other_consumer');
    const one = await invoke('results/feed', { consumerId: consumer });
    expect(one).toMatchObject({ ok: true, value: { items: [{ eventId: event.eventId }] } });
    expect((one as any).value.items).toHaveLength(1);
    expect(await invoke('results/feed', { consumerId: consumer })).toEqual(one);
    expect(await invoke('results/feed', { consumerId: 'other_consumer' })).toMatchObject({ ok: false, error: { code: 'forbidden' } });
    const ack = { schemaVersion: '1.0', consumerId: consumer, eventId: event.eventId, outcome: 'durably_handled' };
    expect(await invoke('results/ack', ack)).toMatchObject({ ok: true, value: { eventId: event.eventId, acknowledged: true } });
    expect(await invoke('results/ack', ack)).toMatchObject({ ok: true, value: { eventId: event.eventId, acknowledged: true } });
    expect(await invoke('results/feed', { consumerId: consumer })).toMatchObject({ ok: true, value: { items: [] } });
    expect(await host.inspect.storage.get<Record<string, unknown>>('intents', event.intentId)).toMatchObject({
      state: 'verified_paid', deliveryState: 'acknowledged', resultEventId: event.eventId, receipt: { status: 'success' },
    });
  });
});

async function seedPaid(ch: string, siteId: string, consumerId: string) {
  const intentId = `psk:v1:intents:${ch.repeat(64)}`;
  const attemptId = `psk:v1:attempts:${ch.repeat(64)}`;
  const reference = `reference-${ch}`;
  const event = await createVerifiedPaymentResult({ intentId, attemptId, formId: 'form_1', formRevision: '1',
    environment: 'test', merchantProfile: profile, amount: { currency: 'NGN', value: '5000.00' },
    verifiedAt: at, providerResourceId: '123', providerReference: reference });
  await host.fixtures.plugin.storage('intents', intentId, { modelVersion: 1, siteId, consumerId,
    merchantId: profile, merchantProfile: profile, environment: 'test', credentialVersion: 1,
    formId: 'form_1', formRevision: '1', identityHmac: intentId, fingerprintHmac: 'e'.repeat(64),
    state: 'verified_paid', deliveryState: 'pending', verifiedAt: at, currentAttemptId: attemptId,
    attempts: [{ modelVersion: 1, id: attemptId, ordinal: 1, state: 'succeeded', providerState: 'success',
      credentialVersion: 1, createTransmissionStarted: true, providerReference: reference, providerResourceId: '123',
      updatedAt: at, nextRunAt: 0 }], protectedSnapshot: { version: 1, algorithm: 'A256GCM', keyId: 'field', iv: 'x', ciphertext: 'x' },
    leaseEpoch: 0, nextRunAt: 0, createdAt: at, updatedAt: at, resultEvent: event, resultEventId: event.eventId,
    receipt: { provider: 'paystack', status: 'success', providerResourceId: '123', providerReference: reference,
      amount: { currency: 'NGN', value: '5000.00' }, domain: 'test', verifiedAt: at },
  });
  return event;
}
async function invoke(route: 'results/feed' | 'results/ack', input: unknown): Promise<unknown> {
  const body = new TextEncoder().encode(JSON.stringify(input));
  const ts = Math.floor(Date.now() / 1000), nonce = `result_nonce_${String(++nonceCounter).padStart(8, '0')}`;
  const hex = (data: Uint8Array) => [...data].map((v) => v.toString(16).padStart(2, '0')).join('');
  const digest = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', body)));
  const frame = canonicalAttestationFrame({ siteId: site, keyId: 'consumer_key', timestampSeconds: ts,
    nonce, method: 'POST', route, bodyDigest: digest });
  const hmac = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = hex(new Uint8Array(await crypto.subtle.sign('HMAC', hmac, new TextEncoder().encode(frame))));
  const response = await host.actions.routes.request(route, { method: 'POST', rawBody: body, user: admin,
    headers: { 'x-emdash-request': '1', 'x-payment-site-id': site, 'x-payment-key-id': 'consumer_key',
      'x-payment-timestamp': String(ts), 'x-payment-nonce': nonce, 'x-payment-signature': signature } });
  return ((await response.json()) as { data: unknown }).data;
}
