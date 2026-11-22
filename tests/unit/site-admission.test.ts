import { describe, expect, it, vi } from 'vite-plus/test';
import { handleSiteSubmit } from '../../src/routes/site.js';
import type { FormDefinition } from '../../src/domain/forms.js';
import type { AdmissionIntentRecord } from '../../src/storage/admission.js';
import type { ModelRecord, VersionedCollection } from '../../src/storage/schema.js';
import type { PaystackCreateDependencies } from '../../src/provider/paystack.js';
import { approvedExamples } from '../support/spec-fixtures.js';

import { createFixture, makeTrustedBody, invoke, invokeSandboxRoute, signedRequest, invokeAction } from '../support/site-admission-fixture.js';

const NOW = 120_000;
const SITE_ID = 'site_1';
const FORM = approvedExamples.fixedForm as unknown as FormDefinition;

describe('Paystack site admission implementation', () => {
	it('authenticates before durable writes, then admits and allocates without provider I/O or plaintext customer data', async () => {
		const fixture = await createFixture();
		const body = makeTrustedBody();
		const invalidSignature = await signedRequest(body, 'nonce_invalid_000001');
		invalidSignature.headers['x-payment-signature'] = '0'.repeat(64);
		const denied = await handleSiteSubmit(invalidSignature.raw, invalidSignature.request, fixture.dependencies);
		expect(denied).toMatchObject({ ok: false, error: { code: 'unauthorized' } });
		expect(fixture.nonces.writeCount).toBe(0);
		expect(fixture.requestKeys.writeCount).toBe(0);
		expect(fixture.forms.writeCount).toBe(0);

		vi.useFakeTimers();
		vi.setSystemTime(NOW);
		const settingsReadsBeforeAdmission = fixture.settingsReadCount();
		const first = await invokeSandboxRoute(fixture, body, 'nonce_admission_00001');
		expect(first).toMatchObject({ ok: true, value: { state: 'initializing', deliveryState: 'not_eligible', stage: 'admission' } });
		expect(fixture.settingsReadCount() - settingsReadsBeforeAdmission).toBe(1);
		expect(fixture.nonces.writeCount + fixture.requestKeys.readCount + fixture.requestKeys.writeCount +
			fixture.forms.readCount + fixture.forms.writeCount + fixture.intents.readCount + fixture.intents.writeCount).toBe(5);
		expect(fixture.forms.values()[0]).toMatchObject({ admissionSequence: 0, state: 'published' });
		expect(fixture.requestKeys.values()).toHaveLength(1);
		expect(fixture.requestKeys.values()[0]).toMatchObject({ stage: 'reserved' });
		expect(JSON.stringify(fixture.requestKeys.values())).not.toContain('payer@example.test');
		expect(JSON.stringify(fixture.requestKeys.values())).not.toContain('member_7');
		expect(JSON.stringify(fixture.requestKeys.values())).not.toContain('order_1');

		const beforeSecondStageCalls = fixture.settingsReadCount() + fixture.nonces.writeCount +
			fixture.requestKeys.readCount + fixture.requestKeys.writeCount + fixture.forms.readCount + fixture.forms.writeCount +
			fixture.intents.readCount + fixture.intents.writeCount;
		const middle = await invokeSandboxRoute(fixture, body, 'nonce_admission_middle_01');
		expect(middle).toMatchObject({ ok: true, value: { state: 'initializing', stage: 'allocation' } });
		const second = await invokeSandboxRoute(fixture, body, 'nonce_allocation_00002');
		expect(second).toMatchObject({
			ok: true,
			value: {
				state: 'created', deliveryState: 'not_eligible', stage: 'provider_work', outcome: 'new_attempt',
				amount: { currency: 'NGN', value: '5000.00' },
			},
		});
		const afterSecondStageCalls = fixture.settingsReadCount() + fixture.nonces.writeCount +
			fixture.requestKeys.readCount + fixture.requestKeys.writeCount + fixture.forms.readCount + fixture.forms.writeCount +
			fixture.intents.readCount + fixture.intents.writeCount;
		expect(afterSecondStageCalls - beforeSecondStageCalls).toBe(14);
		vi.useRealTimers();
		expect(fixture.intents.values()).toHaveLength(1);
		expect(fixture.intents.values()[0]?.attempts[0]).toMatchObject({
			state: 'created', providerState: 'not_started', createTransmissionStarted: false, providerReference: null,
		});
		expect(fixture.requestKeys.values()[0]).toMatchObject({ stage: 'allocated', accepted: true });
		expect(JSON.stringify(fixture.intents.values())).not.toContain('payer@example.test');
		expect(JSON.stringify(fixture.intents.values())).not.toContain('member_7');
		expect(JSON.stringify(fixture.intents.values())).not.toContain('order_1');

		const archived = { ...fixture.forms.values()[0]!, state: 'archived' as const,
			definition: { ...FORM, revision: '2', state: 'archived' as const } };
		fixture.forms.seed(FORM.id, archived);
		const alternateKey = makeTrustedBody('request_key_alternate_123');
		const duplicate = await invoke(fixture.dependencies, alternateKey, 'nonce_duplicate_00003');
		expect(duplicate).toMatchObject({
			ok: true,
			value: { state: 'created', stage: 'provider_work', outcome: 'existing_intent' },
		});
		expect(fixture.forms.values()[0]?.admissionSequence).toBe(1);
		expect(fixture.intents.values()).toHaveLength(1);
		expect(fixture.requestKeys.values()).toHaveLength(2);
		expect(new Set(fixture.requestKeys.values().map((record) => record.attemptId)).size).toBe(1);
		expect(fixture.requestKeys.values()[1]).toHaveProperty('admittedSnapshot.ciphertext');
		const replay = await invoke(fixture.dependencies, alternateKey, 'nonce_duplicate_00004');
		expect(replay).toMatchObject({ ok: true, value: { stage: 'provider_work', outcome: 'existing_intent' } });
		expect(fixture.intents.values()).toHaveLength(1);
	});

	it('freezes the configured consumer across admission and key rotation', async () => {
		const fixture = await createFixture(['consumer_a']);
		const body = makeTrustedBody();
		await invoke(fixture.dependencies, body, 'nonce_consumer_reserve_01');
		await invoke(fixture.dependencies, body, 'nonce_consumer_admit_001');
		await fixture.setConsumers(['consumer_b']);
		const allocated = await invoke(fixture.dependencies, body, 'nonce_consumer_allocate_1');
		expect(allocated).toMatchObject({ ok: true, value: { state: 'created' } });
		expect(fixture.intents.values()[0]).toMatchObject({ consumerId: 'consumer_a' });
	});

	it('rejects ambiguous consumer bindings before reserving a request key', async () => {
		const fixture = await createFixture(['consumer_a', 'consumer_b']);
		const response = await invoke(fixture.dependencies, makeTrustedBody(), 'nonce_consumer_ambiguous1');
		expect(response).toMatchObject({ ok: false, error: { code: 'review_required' } });
		expect(fixture.requestKeys.writeCount).toBe(0);
		expect(fixture.intents.writeCount).toBe(0);
	});

	it('does not loop or allocate when the published-form admission CAS conflicts', async () => {
		const fixture = await createFixture();
		await invoke(fixture.dependencies, makeTrustedBody(), 'nonce_form_reserve_001');
		fixture.forms.conflictNextCas();
		const response = await invoke(fixture.dependencies, makeTrustedBody(), 'nonce_form_cas_00001');
		expect(response).toMatchObject({ ok: true, value: { state: 'initializing', stage: 'admission' } });
		expect(fixture.forms.compareAndSetCalls).toBe(1);
		expect(fixture.intents.writeCount).toBe(0);
		expect(fixture.requestKeys.values()).toHaveLength(1);
		expect(fixture.requestKeys.values()[0]).toMatchObject({ stage: 'reserved', attemptId: null });
	});

	it('adopts admitted-snapshot and attempt-binding writes after their responses are lost', async () => {
		const fixture = await createFixture();
		await invoke(fixture.dependencies, makeTrustedBody(), 'nonce_snapshot_reserve_01');
		fixture.requestKeys.throwAfterApplyOnCas(2);
		const admitted = await invoke(fixture.dependencies, makeTrustedBody(), 'nonce_lost_snapshot_001');
		expect(admitted).toMatchObject({ ok: true, value: { state: 'initializing', stage: 'admission' } });
		expect(fixture.requestKeys.values()[0]).toMatchObject({ stage: 'admitted', admissionSequence: 1 });

		fixture.requestKeys.throwAfterApplyOnCas(3);
		const allocation = await invoke(fixture.dependencies, makeTrustedBody(), 'nonce_lost_binding_0001');
		expect(allocation).toMatchObject({ ok: true, value: { state: 'initializing', stage: 'allocation' } });
		expect(fixture.intents.values()).toHaveLength(1);
		expect(fixture.requestKeys.values()[0]).toMatchObject({ stage: 'allocated', accepted: true });

		const adopted = await invoke(fixture.dependencies, makeTrustedBody(), 'nonce_adopt_binding_001');
		expect(adopted).toMatchObject({ ok: true, value: { state: 'created', stage: 'provider_work', outcome: 'existing_intent' } });
		expect(fixture.forms.values()[0]?.admissionSequence).toBe(1);
		expect(fixture.intents.values()).toHaveLength(1);
	});

	it('rejects a protected fixed-price override before reserving a request key', async () => {
		const fixture = await createFixture();
		const body = makeTrustedBody() as { submission: Record<string, unknown> };
		body.submission.amount = '5000.00';
		const response = await invoke(fixture.dependencies, body, 'nonce_price_override_01');
		expect(response).toMatchObject({ ok: false, error: { code: 'protected_field_override' } });
		expect(fixture.requestKeys.writeCount).toBe(0);
		expect(fixture.forms.compareAndSetCalls).toBe(0);
		expect(fixture.intents.writeCount).toBe(0);
	});

});

describe('Paystack owned action implementation', () => {
	it('returns only the exact current owned hosted action and never changes payment state', async () => {
		const fixture = await createFixture();
		await invoke(fixture.dependencies, makeTrustedBody(), 'nonce_action_reserve_01');
		await invoke(fixture.dependencies, makeTrustedBody(), 'nonce_action_admit_001');
		const allocated = await invoke(fixture.dependencies, makeTrustedBody(), 'nonce_action_allocate_01');
		expect(allocated).toMatchObject({ ok: true, value: { state: 'created', stage: 'provider_work' } });
		const intent = fixture.intents.values()[0]!;
		const initialAttempt = intent.attempts[0]!;
		const nextAction = {
			id: initialAttempt.id,
			kind: 'redirect',
			destination: 'https://checkout.paystack.com/checkout_123',
		};
		fixture.intents.seed(intent.identityHmac, {
			...intent,
			state: 'requires_action',
			attempts: [{
				...initialAttempt,
				state: 'requires_action',
				providerState: 'initialized',
				createTransmissionStarted: true,
				providerReference: 'paystack-reference-123',
				providerResourceId: null,
				providerPayloadDigest: 'a'.repeat(64),
				nextAction,
				nextRunAt: Number.MAX_SAFE_INTEGER,
			}],
		} as unknown as AdmissionIntentRecord);

		const actionRequest = {
			schemaVersion: '1.0', siteId: SITE_ID, subject: { kind: 'member', id: 'member_7' },
			merchantProfile: 'merchant_profile_1', intentId: intent.identityHmac,
			attemptId: initialAttempt.id, actionId: initialAttempt.id,
			siteOrigin: 'https://shop.example', callbackUrl: 'https://shop.example/payments/return',
		};
		const readBefore = fixture.intents.readCount;
		const result = await invokeAction(fixture, actionRequest, 'nonce_action_current_01');
		expect(result).toMatchObject({ ok: true, value: {
			intentId: intent.identityHmac,
			attemptId: initialAttempt.id,
			state: 'requires_action',
			deliveryState: 'not_eligible',
			nextAction,
		} });
		expect(fixture.intents.readCount - readBefore).toBe(1);

		const wrongSubject = await invokeAction(fixture, {
			...actionRequest, subject: { kind: 'member', id: 'other_member' },
		}, 'nonce_action_wrong_subject_01');
		expect(wrongSubject).toMatchObject({ ok: false, error: { code: 'forbidden' } });
		const staleAction = await invokeAction(fixture, { ...actionRequest, actionId: `psk:v1:attempts:${'c'.repeat(64)}` }, 'nonce_action_stale_0001');
		expect(staleAction).toMatchObject({ ok: false, error: { code: 'forbidden' } });

		fixture.intents.seed(intent.identityHmac, {
			...fixture.intents.values()[0]!,
			attempts: [{
				...fixture.intents.values()[0]!.attempts[0]!,
				nextAction: { ...nextAction, instructions: 'must never reach the response' },
			}],
		} as unknown as AdmissionIntentRecord);
		const oppositeActionField = await invokeAction(fixture, actionRequest, 'nonce_action_opposite_001');
		expect(oppositeActionField).toMatchObject({ ok: false, error: { code: 'storage_unavailable' } });
		expect(JSON.stringify(oppositeActionField)).not.toContain('must never reach the response');
	});

	it('starts the current untransmitted attempt once and returns its persisted hosted action on replay', async () => {
		const fixture = await createFixture();
		await invoke(fixture.dependencies, makeTrustedBody(), 'nonce_start_reservation_1');
		await invoke(fixture.dependencies, makeTrustedBody(), 'nonce_start_admission_001');
		await invoke(fixture.dependencies, makeTrustedBody(), 'nonce_start_allocation_01');
		const intent = fixture.intents.values()[0]!;
		const attempt = intent.attempts[0]!;
		const calls: Array<{ url: string; init?: RequestInit }> = [];
		const provider: Omit<PaystackCreateDependencies, 'pluginId'> = {
			settings: fixture.dependencies.settings,
			intents: fixture.intents as unknown as VersionedCollection<ModelRecord>,
			budgets: fixture.budgets,
			fetch: async (url, init) => {
				calls.push({ url, ...(init ? { init } : {}) });
				const payload = JSON.parse(String(init?.body)) as { reference: string; callback_url: string; channels: string[] };
				expect(payload.callback_url).toBe('https://shop.example/payments/return');
				expect(payload.channels).toEqual(['card']);
				return new Response(JSON.stringify({
					status: true,
					data: { reference: payload.reference, authorization_url: 'https://checkout.paystack.com/checkout_123' },
				}), { status: 200, headers: { 'content-type': 'application/json' } });
			},
			now: () => NOW,
			randomBytes: (length) => new Uint8Array(length).fill(16),
		};
		const request = {
			schemaVersion: '1.0', siteId: SITE_ID, subject: { kind: 'member', id: 'member_7' },
			merchantProfile: 'merchant_profile_1', intentId: intent.identityHmac,
			attemptId: attempt.id, actionId: attempt.id,
			siteOrigin: 'https://shop.example', callbackUrl: 'https://shop.example/payments/return',
		};

		const started = await invokeAction(fixture, request, 'nonce_start_action_0001', provider);
		expect(started).toMatchObject({ ok: true, value: {
			intentId: intent.identityHmac, attemptId: attempt.id, state: 'requires_action',
			nextAction: { id: attempt.id, kind: 'redirect', destination: 'https://checkout.paystack.com/checkout_123' },
		} });
		expect(calls).toHaveLength(1);
		expect(calls[0]?.url).toBe('https://api.paystack.co/transaction/initialize');

		const replay = await invokeAction(fixture, request, 'nonce_start_action_0002', provider);
		expect(replay).toMatchObject({ ok: true, value: {
			state: 'requires_action', nextAction: { id: attempt.id, kind: 'redirect', destination: 'https://checkout.paystack.com/checkout_123' },
		} });
		expect(calls).toHaveLength(1);
	});
});
