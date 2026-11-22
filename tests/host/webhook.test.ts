import { afterEach, beforeEach, describe, expect, it } from 'vite-plus/test';
import { createPluginRuntimeTestHost, type PluginRuntimeTestHost } from '@emdash-cms/plugin-test';
import { MAX_PAYSTACK_WEBHOOK_BYTES } from '../../src/routes/webhook.js';
import { createDataEncryptionKey, createIndexHmacKey, encodeBase64Url, encryptValue, hmacIndex } from '../../src/security/encryption.js';
import { createPaystackReference } from '../../src/provider/paystack-reference.js';
import type { AdmittedPaymentSnapshot } from '../../src/storage/admission.js';
import { deterministicRecordId } from '../../src/storage/schema.js';
import { approvedExamples } from '../support/spec-fixtures.js';

let host: PluginRuntimeTestHost;
let admin: Awaited<ReturnType<PluginRuntimeTestHost['fixtures']['user']>>;
const PROFILE = 'merchant_profile_1';
const SECRET = 'sk_test_host_webhook_fixture';
const FIELD_KEY = new Uint8Array(32).fill(4);
const IDENTITY_KEY = new Uint8Array(32).fill(5);
const REFERENCE = `psk-${'e'.repeat(40)}`;
const LINKED_INTENT_ID = `psk:v1:intents:${'c'.repeat(64)}`;
const LINKED_ATTEMPT_ID = `psk:v1:attempts:${'d'.repeat(64)}`;

describe('Paystack webhook through the sandboxed EmDash host', () => {
	beforeEach(async () => {
		host = await createPluginRuntimeTestHost();
		admin = await host.fixtures.user({ email: 'webhook-admin@example.test', role: 'admin' });
		await host.fixtures.plugin.setting('paymentConfiguration', JSON.stringify({
			schemaVersion: 1,
			paused: false,
			activeProfile: PROFILE,
			profiles: {
				[PROFILE]: {
					profileId: PROFILE,
					activeCredentialVersion: 1,
					credentialVersions: [{ version: 1, environment: 'test', secretKey: SECRET }],
				},
			},
			integrationKeys: [],
			fieldEncryptionKeyRing: { activeKeyId: 'field-v1', keys: [{ keyId: 'field-v1', material: encodeBase64Url(FIELD_KEY) }] },
			identityHmacKeyRing: { activeKeyId: 'identity-v1', keys: [{ keyId: 'identity-v1', material: encodeBase64Url(IDENTITY_KEY) }] },
		}));
	});

	afterEach(async () => {
		await host?.dispose();
	});

	it('returns raw HTTP 200 only after storing a compact semantic inbox record', async () => {
		const body = new TextEncoder().encode(JSON.stringify({
			event: 'charge.success',
			data: { reference: REFERENCE, id: 4_045_667_488, email: 'private@example.test', authorization: { bin: '411111' } },
		}));
		const signature = await signatureHex(body, SECRET);
		const first = await host.actions.routes.request('provider/webhook', {
			method: 'POST', rawBody: body, headers: { 'x-paystack-signature': signature },
		});
		expect(first.status).toBe(200);
		expect(await first.text()).toBe('accepted');

		const semanticKey = await hmacIndex(
			['paystack-webhook-v1', PROFILE, 'test', 'charge.success', REFERENCE],
			createIndexHmacKey('identity-v1', IDENTITY_KEY),
		);
		const record = await host.inspect.storage.get<Record<string, unknown>>('inbox', deterministicRecordId('inbox', semanticKey));
		expect(record).toMatchObject({ profileId: PROFILE, environment: 'test', reference: REFERENCE, state: 'accepted', intentId: null });
		expect(record).not.toHaveProperty('rawBody');
		expect(record).not.toHaveProperty('email');
		expect(record).not.toHaveProperty('authorization');

		const duplicate = await host.actions.routes.request('provider/webhook', {
			method: 'POST', rawBody: body, headers: { 'x-paystack-signature': signature },
		});
		expect(duplicate.status).toBe(200);
		expect(await duplicate.text()).toBe('accepted');
		expect(await host.inspect.storage.get('inbox', deterministicRecordId('inbox', semanticKey))).toEqual(record);
	});

	it('rejects bad signatures with a raw 401 and no inbox write', async () => {
		const body = new TextEncoder().encode(JSON.stringify({ event: 'charge.success', data: { reference: REFERENCE } }));
		const semanticKey = await hmacIndex(
			['paystack-webhook-v1', PROFILE, 'test', 'charge.success', REFERENCE],
			createIndexHmacKey('identity-v1', IDENTITY_KEY),
		);
		const response = await host.actions.routes.request('provider/webhook', {
			method: 'POST', rawBody: body, headers: { 'x-paystack-signature': 'a'.repeat(128) },
		});
		expect(response.status).toBe(401);
		expect(await response.text()).toBe('invalid signature');
		expect(await host.inspect.storage.get('inbox', deterministicRecordId('inbox', semanticKey))).toBeNull();
	});

	it('enforces the declared byte ceiling with a raw HTTP 413', async () => {
		const response = await host.actions.routes.request('provider/webhook', {
			method: 'POST',
			rawBody: new Uint8Array(MAX_PAYSTACK_WEBHOOK_BYTES + 1),
			headers: { 'x-paystack-signature': 'a'.repeat(128) },
		});
		expect(response.status).toBe(413);
		expect(response.headers.get('content-type')).toContain('text/plain');
		expect(await response.text()).toBe('too large');
	});

	it('recovers an accepted signed event after restart and atomically commits verified payment once', async () => {
		const reference = createPaystackReference(LINKED_INTENT_ID, 1)!;
		const { eventId, semanticKey } = await seedLinkedIntent(reference);
		await host.http.respond(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, verificationResponse(reference));
		const rawBody = webhookBytes(reference, '4045667488');
		const accepted = await postWebhook(rawBody);
		expect(accepted.status).toBe(200);
		const admitted = await host.inspect.storage.get<Record<string, unknown>>('inbox', eventId);
		expect(admitted).toMatchObject({ state: 'accepted', intentId: LINKED_INTENT_ID, attemptId: LINKED_ATTEMPT_ID });

		await host.restart();
		const reconciled = await postReconciliation(eventId);
		expect(reconciled.status).toBe(200);
		expect(await reconciled.json()).toMatchObject({ success: true, data: { ok: true, value: { processed: 1, remainingUnresolved: 0 } } });
		expect(await host.inspect.storage.get<Record<string, unknown>>('intents', LINKED_INTENT_ID)).toMatchObject({
			state: 'verified_paid', deliveryState: 'pending', receipt: { status: 'success', providerReference: reference },
			resultEvent: { type: 'payment.verified', intentId: LINKED_INTENT_ID, attemptId: LINKED_ATTEMPT_ID },
		});
		expect(await host.inspect.storage.get<Record<string, unknown>>('inbox', eventId)).toMatchObject({ state: 'done', semanticKey });
		expect(host.http.requests()).toHaveLength(1);

		await host.restart();
		const duplicate = await postReconciliation(eventId);
		expect(duplicate.status).toBe(200);
		expect(await duplicate.json()).toMatchObject({ success: true, data: { ok: true, value: { processed: 0, remainingUnresolved: 0 } } });
		expect(host.http.requests()).toHaveLength(1);
	});

	it('recovers a paid aggregate after restart when inbox completion was interrupted', async () => {
		const reference = createPaystackReference(LINKED_INTENT_ID, 1)!;
		const { eventId } = await seedLinkedIntent(reference);
		await host.http.respond(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, verificationResponse(reference));
		await postWebhook(webhookBytes(reference, '4045667488'));
		await postReconciliation(eventId);
		const paidIntent = await host.inspect.storage.get<Record<string, unknown>>('intents', LINKED_INTENT_ID);
		expect(paidIntent).toMatchObject({ state: 'verified_paid' });

		// Recreate the durable crash boundary: payment CAS committed while inbox completion did not.
		const acceptedAgain = { ...await host.inspect.storage.get<Record<string, unknown>>('inbox', eventId), state: 'processing', dueAt: 0 };
		await host.fixtures.plugin.storage('inbox', eventId, acceptedAgain);
		await host.restart();
		const recovered = await postReconciliation(eventId);
		expect(recovered.status).toBe(200);
		expect(await recovered.json()).toMatchObject({ success: true, data: { ok: true, value: { processed: 1, remainingUnresolved: 0 } } });
		expect(await host.inspect.storage.get<Record<string, unknown>>('inbox', eventId)).toMatchObject({ state: 'done' });
		expect(host.http.requests()).toHaveLength(1);
	});

	it('withholds payment on provider expectation mismatch and reviews unlinked signed events', async () => {
		const reference = createPaystackReference(LINKED_INTENT_ID, 1)!;
		const { eventId: linkedEventId } = await seedLinkedIntent(reference);
		await host.http.respond(`https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`, verificationResponse(reference, { amount: 500001 }));
		await postWebhook(webhookBytes(reference, '4045667488'));
		await postReconciliation(linkedEventId);
		expect(await host.inspect.storage.get<Record<string, unknown>>('intents', LINKED_INTENT_ID)).toMatchObject({
			state: 'review_required', deliveryState: 'not_eligible', verificationState: 'mismatch',
		});
		expect(await host.inspect.storage.get<Record<string, unknown>>('inbox', linkedEventId)).toMatchObject({ state: 'review' });
		expect(await host.inspect.storage.get<Record<string, unknown>>('intents', LINKED_INTENT_ID)).not.toHaveProperty('resultEvent');

		const resourceIntentId = `psk:v1:intents:${'8'.repeat(64)}`;
		const resourceAttemptId = `psk:v1:attempts:${'9'.repeat(64)}`;
		const resourceReference = createPaystackReference(resourceIntentId, 1)!;
		const { eventId: resourceEventId } = await seedLinkedIntent(resourceReference, resourceIntentId, resourceAttemptId);
		await host.http.respond(`https://api.paystack.co/transaction/verify/${encodeURIComponent(resourceReference)}`, verificationResponse(resourceReference));
		await postWebhook(webhookBytes(resourceReference, '4045667489'));
		await postReconciliation(resourceEventId);
		expect(await host.inspect.storage.get<Record<string, unknown>>('intents', resourceIntentId)).toMatchObject({
			state: 'review_required', deliveryState: 'not_eligible', verificationState: 'mismatch',
		});
		expect(await host.inspect.storage.get<Record<string, unknown>>('intents', resourceIntentId)).not.toHaveProperty('resultEvent');

		const unknownReference = `psk-${'f'.repeat(40)}`;
		const unmatchedBody = webhookBytes(unknownReference, '4045667489');
		const unmatched = await postWebhook(unmatchedBody);
		expect(unmatched.status).toBe(200);
		const unmatchedSemanticKey = await hmacIndex(
			['paystack-webhook-v1', PROFILE, 'test', 'charge.success', unknownReference],
			createIndexHmacKey('identity-v1', IDENTITY_KEY),
		);
		const unmatchedEventId = deterministicRecordId('inbox', unmatchedSemanticKey);
		expect(await host.inspect.storage.get<Record<string, unknown>>('inbox', unmatchedEventId)).toMatchObject({
			state: 'accepted', intentId: null, attemptId: null,
		});
		const before = host.http.requests().length;
		const marked = await postReconciliation(unmatchedEventId);
		expect(marked.status).toBe(200);
		expect(await marked.json()).toMatchObject({ success: true, data: { ok: false, error: { code: 'review_required' } } });
		expect(await host.inspect.storage.get<Record<string, unknown>>('inbox', unmatchedEventId)).toMatchObject({ state: 'review' });
		expect(host.http.requests()).toHaveLength(before);
	});

	it('keeps reconciliation behind host authentication, permission, and mutation CSRF', async () => {
		const eventId = deterministicRecordId('inbox', 'a'.repeat(64));
		const anonymous = await host.actions.routes.request('reconciliation', { method: 'POST', body: { eventId } });
		expect(anonymous.status).toBe(401);
		const subscriber = await host.fixtures.user({ email: 'webhook-subscriber@example.test', role: 'subscriber' });
		const denied = await host.actions.routes.request('reconciliation', {
			method: 'POST', body: { eventId }, user: subscriber,
		});
		expect(denied.status).toBe(403);
		const csrfDenied = await host.actions.routes.request('reconciliation', {
			method: 'POST', body: { eventId }, user: admin,
		});
		expect(csrfDenied.status).toBe(403);
		expect(host.http.requests()).toHaveLength(0);
	});
});

async function seedLinkedIntent(
	reference: string,
	intentId = LINKED_INTENT_ID,
	attemptId = LINKED_ATTEMPT_ID,
): Promise<{ eventId: string; semanticKey: string }> {
	const form = approvedExamples.fixedForm;
	const snapshot: AdmittedPaymentSnapshot = {
		schemaVersion: '1.0', siteId: 'site_1', subject: { kind: 'member', id: 'member_1' }, businessReference: 'order_1',
		merchantProfile: PROFILE, environment: 'test', credentialVersion: 1, form,
		amount: { currency: 'NGN', value: '5000.00', minorUnits: 500_000 }, fields: { payer_email: 'payer@example.test' }, metadata: {},
	};
	const encryptionKey = createDataEncryptionKey('field-v1', FIELD_KEY);
	const protectedSnapshot = await encryptValue(snapshot, encryptionKey, {
		pluginId: host.manifest.id, collection: 'intents', recordId: intentId, schemaVersion: 1, purpose: 'custom_fields',
	});
	const at = new Date(Date.now() - 60_000).toISOString();
	await host.fixtures.plugin.storage('intents', intentId, {
		modelVersion: 1, siteId: 'site_1', merchantId: PROFILE, merchantProfile: PROFILE, environment: 'test', credentialVersion: 1,
		formId: form.id, formRevision: form.revision, identityHmac: intentId, fingerprintHmac: 'a'.repeat(64),
		state: 'unknown', deliveryState: 'not_eligible', currentAttemptId: attemptId,
		attempts: [{ modelVersion: 1, id: attemptId, ordinal: 1, predecessorId: null, state: 'unknown', providerState: 'unknown',
			credentialVersion: 1, createTransmissionStarted: true, providerReference: reference, providerResourceId: null,
			createdAt: at, updatedAt: at, nextRunAt: Date.now() }],
		protectedSnapshot, leaseEpoch: 1, nextRunAt: Date.now(), createdAt: at, updatedAt: at,
	});
	const semanticKey = await hmacIndex(
		['paystack-webhook-v1', PROFILE, 'test', 'charge.success', reference],
		createIndexHmacKey('identity-v1', IDENTITY_KEY),
	);
	return { eventId: deterministicRecordId('inbox', semanticKey), semanticKey };
}

function verificationResponse(reference: string, patch: Record<string, unknown> = {}) {
	return new Response(JSON.stringify({ status: true, message: 'Verification successful', data: {
		id: 4045667488, domain: 'test', status: 'success', reference, amount: 500000, currency: 'NGN', channel: 'card',
		customer: { id: 1001, email: 'payer@example.test' }, ...patch,
	} }), { status: 200, headers: { 'content-type': 'application/json' } });
}

function webhookBytes(reference: string, resourceId: string): Uint8Array {
	return new TextEncoder().encode(JSON.stringify({ event: 'charge.success', data: { reference, id: resourceId, email: 'private@example.test' } }));
}

async function postWebhook(rawBody: Uint8Array): Promise<Response> {
	const body = rawBody.buffer.slice(rawBody.byteOffset, rawBody.byteOffset + rawBody.byteLength) as ArrayBuffer;
	return host.actions.routes.request('provider/webhook', {
		method: 'POST', rawBody: body, headers: { 'x-paystack-signature': await signatureHex(rawBody, SECRET) },
	});
}

async function postReconciliation(eventId: string): Promise<Response> {
	return host.actions.routes.request('reconciliation', {
		method: 'POST', headers: { 'x-emdash-request': '1' }, body: { eventId }, user: admin,
	});
}

async function signatureHex(body: Uint8Array, secret: string): Promise<string> {
	const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
	const bodyBuffer = body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) as ArrayBuffer;
	return [...new Uint8Array(await crypto.subtle.sign('HMAC', key, bodyBuffer))]
		.map((byte) => byte.toString(16).padStart(2, '0')).join('');
}
