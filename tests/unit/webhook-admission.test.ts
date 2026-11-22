import { describe, expect, it } from 'vite-plus/test';
import { handlePaystackWebhook, MAX_PAYSTACK_WEBHOOK_BYTES, MAX_WEBHOOK_CREDENTIAL_VERSIONS } from '../../src/routes/webhook.js';
import { createPaystackReference } from '../../src/provider/paystack-reference.js';
import type { ModelRecord } from '../../src/storage/schema.js';

import {
  PROFILE, OLD_SECRET, CURRENT_SECRET, URL, MemoryInbox, MemoryIntents,
  configuration, dependencies, signature, send, eventBytes,
} from '../support/webhook-fixture.js';

describe('Paystack webhook admission', () => {
	it('correlates reused secret values to the immutable credential version on the exact attempt', async () => {
		const intentId = `psk:v1:intents:${'b'.repeat(64)}`;
		const attemptId = `psk:v1:attempts:${'c'.repeat(64)}`;
		const reference = createPaystackReference(intentId, 1)!;
		const setting = configuration([
			{ version: 1, environment: 'test', secretKey: CURRENT_SECRET },
			{ version: 2, environment: 'test', secretKey: CURRENT_SECRET },
		]);
		const intent: ModelRecord = {
			modelVersion: 1, siteId: 'site_1', merchantId: PROFILE, merchantProfile: PROFILE, environment: 'test', credentialVersion: 1,
			formId: 'fixed_form', formRevision: '1', identityHmac: intentId, fingerprintHmac: 'b'.repeat(64), state: 'unknown',
			deliveryState: 'not_eligible', currentAttemptId: attemptId, attempts: [{
				modelVersion: 1, id: attemptId, ordinal: 1, state: 'unknown', providerState: 'unknown', credentialVersion: 1,
				createTransmissionStarted: true, providerReference: reference, nextRunAt: 0, updatedAt: '2026-10-18T09:00:00.000Z',
			}],
			protectedSnapshot: { version: 1, algorithm: 'A256GCM', keyId: 'field-v1', iv: 'AA', ciphertext: 'AA' },
			leaseEpoch: 0, nextRunAt: 0, createdAt: '2026-10-18T09:00:00.000Z', updatedAt: '2026-10-18T09:00:00.000Z',
		};
		const raw = new TextEncoder().encode(JSON.stringify({ event: 'charge.success', data: { reference, id: 4045667488 } }));
		const fixture = await send(raw, CURRENT_SECRET, dependencies({ setting, intents: new MemoryIntents(intent) }));
		const [, record] = [...fixture.deps.inbox.entries.entries()][0]!;
		expect(fixture.response).toEqual({ status: 200, body: 'accepted' });
		expect(record).toMatchObject({ intentId, attemptId, credentialVersion: 1 });
	});

	it('verifies exact original bytes, admits only compact correlation, and deduplicates semantic variants', async () => {
		const raw = eventBytes('"status":"success"', ' ');
		const first = await send(raw, OLD_SECRET);
		expect(first.response).toEqual({ status: 200, body: 'accepted' });
		expect(first.deps.settings.reads).toBe(1);
		expect(first.deps.inbox.reads).toBe(1);
		expect(first.deps.inbox.writes).toBe(1);
		const [id, record] = [...first.deps.inbox.entries.entries()][0]!;
		expect(id).toMatch(/^psk:v1:inbox:[a-f0-9]{64}$/u);
		expect(record).toMatchObject({
			modelVersion: 1, profileId: PROFILE, environment: 'test', credentialVersion: 1,
			eventType: 'charge.success', reference: `psk-${'a'.repeat(40)}`,
			providerResourceId: '4045667488', intentId: null, attemptId: null, state: 'accepted', leaseEpoch: 0,
		});
		expect(record).not.toHaveProperty('rawBody');
		expect(record).not.toHaveProperty('email');
		expect(record).not.toHaveProperty('authorization');
		expect(new TextEncoder().encode(JSON.stringify(record)).byteLength).toBeLessThan(4096);

		const variant = eventBytes('"status":"success"', '\n ');
		const repeated = await send(variant, OLD_SECRET, first.deps);
		expect(repeated.response).toEqual({ status: 200, body: 'accepted' });
		expect(repeated.deps.inbox.writes).toBe(1);
		expect(repeated.deps.inbox.entries.size).toBe(1);
	});

	it('rejects an invalid signature after one settings read and before any storage call', async () => {
		const raw = eventBytes();
		const deps = dependencies();
		const response = await handlePaystackWebhook(raw, {
			method: 'POST', url: URL, headers: { 'x-paystack-signature': 'a'.repeat(128) },
		}, deps.value);
		expect(response.status).toBe(401);
		expect(deps.settings.reads).toBe(1);
		expect(deps.inbox.reads + deps.inbox.writes).toBe(0);
	});

	it('does not try credentials from another merchant profile', async () => {
		const raw = eventBytes();
		const deps = dependencies();
		const response = await handlePaystackWebhook(raw, {
			method: 'POST', url: URL, headers: { 'x-paystack-signature': await signature(raw, 'sk_test_other_fixture') },
		}, deps.value);
		expect(response.status).toBe(401);
		expect(deps.settings.reads).toBe(1);
		expect(deps.inbox.reads + deps.inbox.writes).toBe(0);
	});

	it('authenticates before parsing and rejects malformed signed JSON without a storage call', async () => {
		const raw = new TextEncoder().encode('{"event":');
		const { response, deps } = await send(raw);
		expect(response).toEqual({ status: 400, body: 'invalid request' });
		expect(deps.settings.reads).toBe(1);
		expect(deps.inbox.reads + deps.inbox.writes).toBe(0);
	});

	it('rejects oversized input before reading settings', async () => {
		const deps = dependencies();
		const response = await handlePaystackWebhook(new Uint8Array(MAX_PAYSTACK_WEBHOOK_BYTES + 1), {
			method: 'POST', url: URL, headers: { 'x-paystack-signature': 'a'.repeat(128) },
		}, deps.value);
		expect(response).toEqual({ status: 413, body: 'too large' });
		expect(deps.settings.reads).toBe(0);
		expect(deps.inbox.reads + deps.inbox.writes).toBe(0);
	});

	it('fails closed instead of scanning an unbounded credential history', async () => {
		const versions = Array.from({ length: MAX_WEBHOOK_CREDENTIAL_VERSIONS + 1 }, (_value, index) => ({
			version: index + 1, environment: 'test' as const, secretKey: `sk_test_key_${index}`,
		}));
		const deps = dependencies({ setting: configuration(versions) });
		const response = await handlePaystackWebhook(eventBytes(), {
			method: 'POST', url: URL, headers: { 'x-paystack-signature': 'a'.repeat(128) },
		}, deps.value);
		expect(response).toEqual({ status: 503, body: 'unavailable' });
		expect(deps.settings.reads).toBe(1);
		expect(deps.inbox.reads + deps.inbox.writes).toBe(0);
	});

	it('confirms an applied-but-lost inbox write before returning HTTP 200', async () => {
		const inbox = new MemoryInbox();
		inbox.writeThenThrow = true;
		const { response, deps } = await send(eventBytes(), CURRENT_SECRET, dependencies({ inbox }));
		expect(response).toEqual({ status: 200, body: 'accepted' });
		expect(deps.inbox.writes).toBe(1);
		expect(deps.inbox.reads).toBe(2);
		expect(deps.inbox.entries.size).toBe(1);
	});

	it('returns retryable unavailable when storage cannot confirm durable acceptance', async () => {
		const inbox = new MemoryInbox();
		inbox.throwRead = true;
		const { response, deps } = await send(eventBytes(), CURRENT_SECRET, dependencies({ inbox }));
		expect(response).toEqual({ status: 503, body: 'unavailable' });
		expect(deps.inbox.writes).toBe(0);
	});
});
