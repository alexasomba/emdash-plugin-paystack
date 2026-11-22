import { createPaystackReference } from '../../src/provider/paystack-reference.js';
import { afterEach, beforeEach, describe, expect, it } from 'vite-plus/test';
import { createPluginRuntimeTestHost, type PluginRuntimeTestHost } from '@emdash-cms/plugin-test';
import type { AdmittedPaymentSnapshot } from '../../src/storage/admission.js';
import { canonicalAttestationFrame } from '../../src/security/attestation.js';
import { createDataEncryptionKey, encodeBase64Url, encryptValue } from '../../src/security/encryption.js';
import { approvedExamples } from '../support/spec-fixtures.js';
import { createVerifiedPaymentResult } from '../../src/domain/result.js';

let host: PluginRuntimeTestHost;
let admin: Awaited<ReturnType<PluginRuntimeTestHost['fixtures']['user']>>;
const NOW = Date.now();
const SITE_ID = 'site_1';
const KEY_ID = 'site_key_1';
const PROFILE = 'merchant_profile_1';
const INTENT_ID = `psk:v1:intents:${'a'.repeat(64)}`;
const ATTEMPT_ID = `psk:v1:attempts:${'b'.repeat(64)}`;
const SITE_KEY = new Uint8Array(32).fill(3);
const FIELD_KEY = new Uint8Array(32).fill(4);
const IDENTITY_KEY = new Uint8Array(32).fill(5);

describe('Paystack owned action in the EmDash runtime host', () => {
	beforeEach(async () => {
		host = await createPluginRuntimeTestHost();
		admin = await host.fixtures.user({ email: 'payment-action-admin@example.test', role: 'admin' });
	});

	afterEach(async () => {
		await host?.dispose();
	});

	it.each([false, true])('runs standalone checkout initialization through the sandbox (matching provider response: %s)', async (matches) => {
		await host.fixtures.plugin.setting('paymentConfiguration', JSON.stringify({
			schemaVersion: 1,
			paused: false,
			activeProfile: PROFILE,
			profiles: {
				[PROFILE]: {
					profileId: PROFILE,
					activeCredentialVersion: 1,
					credentialVersions: [{ version: 1, environment: 'test', secretKey: 'sk_test_runtime_fixture' }],
				},
			},
			integrationKeys: [{
				siteId: SITE_ID, keyId: KEY_ID, secretBase64url: encodeBase64Url(SITE_KEY), purpose: 'site-payment',
			}],
			fieldEncryptionKeyRing: { activeKeyId: 'field-v1', keys: [{ keyId: 'field-v1', material: encodeBase64Url(FIELD_KEY) }] },
			identityHmacKeyRing: { activeKeyId: 'identity-v1', keys: [{ keyId: 'identity-v1', material: encodeBase64Url(IDENTITY_KEY) }] },
		}));

		const form = approvedExamples.fixedForm;
		const snapshot: AdmittedPaymentSnapshot = {
			schemaVersion: '1.0',
			siteId: SITE_ID,
			subject: { kind: 'member', id: 'member_7' },
			businessReference: 'order_1',
			merchantProfile: PROFILE,
			environment: 'test',
			credentialVersion: 1,
			form,
			amount: { currency: 'NGN', value: '5000.00', minorUnits: 500_000 },
			fields: { payer_email: 'payer@example.test' },
			metadata: {},
		};
		const encryptionKey = createDataEncryptionKey('field-v1', FIELD_KEY);
		const protectedSnapshot = await encryptValue(snapshot, encryptionKey, {
			pluginId: host.manifest.id, collection: 'intents', recordId: INTENT_ID, schemaVersion: 1, purpose: 'custom_fields',
		});
		const at = new Date(NOW).toISOString();
		await host.fixtures.plugin.storage('intents', INTENT_ID, {
			modelVersion: 1,
			siteId: SITE_ID,
			merchantId: PROFILE,
			merchantProfile: PROFILE,
			environment: 'test',
			credentialVersion: 1,
			formId: form.id,
			formRevision: form.revision,
			identityHmac: INTENT_ID,
			fingerprintHmac: 'c'.repeat(64),
			state: 'created',
			deliveryState: 'not_eligible',
			currentAttemptId: ATTEMPT_ID,
			attempts: [{
				modelVersion: 1,
				id: ATTEMPT_ID,
				ordinal: 1,
				predecessorId: null,
				state: 'created',
				providerState: 'not_started',
				credentialVersion: 1,
				createTransmissionStarted: false,
				providerReference: null,
				providerResourceId: null,
				createdAt: at,
				updatedAt: at,
				nextRunAt: NOW,
			}],
			protectedSnapshot,
			leaseEpoch: 0,
			nextRunAt: NOW,
			createdAt: at,
			updatedAt: at,
		});

		await host.http.respond('https://api.paystack.co/transaction/initialize', new Response(JSON.stringify({
			status: true,
			data: { reference: matches ? createPaystackReference(INTENT_ID, 1) : 'unrelated-reference', authorization_url: 'https://checkout.paystack.com/checkout_123' },
		}), { status: 200, headers: { 'content-type': 'application/json' } }));

		const first = await invokeAction('nonce_runtime_action_0001');
		if (matches) {
			expect(first).toMatchObject({ ok: true, value: { intentId: INTENT_ID, state: 'requires_action' } });
			expect(await invokeAction('nonce_runtime_action_0002')).toEqual(first);
			expect(host.http.requests()).toHaveLength(1);
			return;
		}

		expect(first).toMatchObject({ ok: true, value: { intentId: INTENT_ID, attemptId: ATTEMPT_ID, state: 'unknown', stage: 'provider_work' } });
		const outbound = host.http.requests();
		expect(outbound).toHaveLength(1);
		expect(outbound[0]).toMatchObject({
			url: 'https://api.paystack.co/transaction/initialize',
			method: 'POST',
			headers: expect.objectContaining({ authorization: 'Bearer sk_test_runtime_fixture' }),
		});
		expect(new TextDecoder().decode(outbound[0]!.body)).toContain('"callback_url":"https://shop.example/payments/return"');
		expect(new TextDecoder().decode(outbound[0]!.body)).not.toContain('sk_test_runtime_fixture');
		expect(await host.inspect.storage.get<Record<string, unknown>>('intents', INTENT_ID)).toMatchObject({
			state: 'unknown',
			attempts: [{ createTransmissionStarted: true, providerState: 'unknown', providerReference: expect.any(String) }],
		});

		const replay = await invokeAction('nonce_runtime_action_0002');
		expect(replay).toMatchObject({ ok: true, value: { state: 'unknown', attemptId: ATTEMPT_ID } });
		expect(host.http.requests()).toHaveLength(1);

		await host.restart();
		const afterRestart = await invokeAction('nonce_runtime_action_0003');
		expect(afterRestart).toMatchObject({ ok: true, value: { state: 'unknown', attemptId: ATTEMPT_ID } });
		expect(host.http.requests()).toHaveLength(1);
		expect(await invokeStatus('nonce_runtime_status_0001', 'member_7')).toMatchObject({ ok: true, value: { state: 'unknown', intentId: INTENT_ID, attemptId: ATTEMPT_ID, amount: { currency: 'NGN', value: '5000.00' } } });
		expect(await invokeStatus('nonce_runtime_status_0001', 'member_7')).toMatchObject({ ok: false, error: { code: 'unauthorized' } });
		expect(await invokeStatus('nonce_runtime_status_0002', 'other_member')).toMatchObject({ ok: false, error: { code: 'forbidden' } });
		expect(host.http.requests()).toHaveLength(1);
		const current = await host.inspect.storage.get<Record<string, any>>('intents', INTENT_ID);
		const reference = current!.attempts[0].providerReference;
		const event = await createVerifiedPaymentResult({ intentId: INTENT_ID, attemptId: ATTEMPT_ID, formId: form.id,
			formRevision: form.revision, environment: 'test', merchantProfile: PROFILE, amount: { currency: 'NGN', value: snapshot.amount.value },
			verifiedAt: at, providerResourceId: '123', providerReference: reference });
		const paid = { ...current!, state: 'verified_paid', deliveryState: 'pending', resultEvent: event, resultEventId: event.eventId,
			attempts: [{ ...current!.attempts[0], state: 'succeeded', providerState: 'success', providerResourceId: '123', nextAction: null }],
			receipt: { provider: 'paystack', status: 'success', providerResourceId: '123', providerReference: reference,
				amount: event.amount, domain: 'test', verifiedAt: at } };
		await host.fixtures.plugin.storage('intents', INTENT_ID, paid);
		expect(await invokeStatus('nonce_runtime_status_0003', 'member_7')).toMatchObject({ ok: true, value: { state: 'verified_paid', stage: 'complete' } });
		await host.fixtures.plugin.storage('intents', INTENT_ID, { ...paid, resultEventId: 'invalid' });
		expect(await invokeStatus('nonce_runtime_status_0004', 'member_7')).toMatchObject({ ok: false, error: { code: 'storage_unavailable' } });
		const wrongAmount = { ...event, amount: { currency: 'NGN', value: '5001.00' } };
		await host.fixtures.plugin.storage('intents', INTENT_ID, { ...paid, resultEvent: wrongAmount,
			receipt: { ...paid.receipt, amount: wrongAmount.amount } });
		expect(await invokeStatus('nonce_runtime_status_0005', 'member_7')).toMatchObject({ ok: false, error: { code: 'storage_unavailable' } });
	});
});

async function invokeAction(nonce: string): Promise<unknown> {
	const body = new TextEncoder().encode(JSON.stringify({
		schemaVersion: '1.0',
		siteId: SITE_ID,
		subject: { kind: 'member', id: 'member_7' },
		merchantProfile: PROFILE,
		intentId: INTENT_ID,
		attemptId: ATTEMPT_ID,
		actionId: ATTEMPT_ID,
		siteOrigin: 'https://shop.example',
		callbackUrl: 'https://shop.example/payments/return',
	}));
	const timestampSeconds = Math.floor(Date.now() / 1000);
	const bodyDigest = new Uint8Array(await crypto.subtle.digest('SHA-256', body));
	const digestHex = [...bodyDigest].map((value) => value.toString(16).padStart(2, '0')).join('');
	const frame = canonicalAttestationFrame({
		siteId: SITE_ID, keyId: KEY_ID, timestampSeconds, nonce, method: 'POST', route: 'payments/action', bodyDigest: digestHex,
	});
	const key = await crypto.subtle.importKey('raw', SITE_KEY, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const signature = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(frame)));
	const signatureHex = [...signature].map((value) => value.toString(16).padStart(2, '0')).join('');
	const response = await host.actions.routes.request('payments/action', {
		method: 'POST',
		headers: {
			'x-emdash-request': '1',
			'x-payment-site-id': SITE_ID,
			'x-payment-key-id': KEY_ID,
			'x-payment-timestamp': String(timestampSeconds),
			'x-payment-nonce': nonce,
			'x-payment-signature': signatureHex,
		},
		rawBody: body,
		user: admin,
	});
	const envelope = await response.json() as { readonly success: boolean; readonly data: unknown };
	return envelope.data;
}

async function invokeStatus(nonce: string, subject: string): Promise<unknown> {
	const route = 'payments/status';
	const body = new TextEncoder().encode(JSON.stringify({ schemaVersion: '1.0', siteId: SITE_ID,
		subject: { kind: 'member', id: subject }, merchantProfile: PROFILE, intentId: INTENT_ID, attemptId: ATTEMPT_ID }));
	const timestampSeconds = Math.floor(Date.now() / 1000);
	const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', body));
	const hex = (value: Uint8Array) => [...value].map((item) => item.toString(16).padStart(2, '0')).join('');
	const frame = canonicalAttestationFrame({ siteId: SITE_ID, keyId: KEY_ID, timestampSeconds, nonce, method: 'POST', route, bodyDigest: hex(digest) });
	const key = await crypto.subtle.importKey('raw', SITE_KEY, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const signature = hex(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(frame))));
	const response = await host.actions.routes.request(route, { method: 'POST', rawBody: body, user: admin, headers: {
		'x-emdash-request': '1', 'x-payment-site-id': SITE_ID, 'x-payment-key-id': KEY_ID,
		'x-payment-timestamp': String(timestampSeconds), 'x-payment-nonce': nonce, 'x-payment-signature': signature } });
	return ((await response.json()) as { data: unknown }).data;
}
