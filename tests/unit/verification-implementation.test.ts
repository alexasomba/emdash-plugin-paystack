import { describe, expect, it, vi } from 'vite-plus/test';
import type { PluginContext } from 'emdash/plugin';
import { verifyPaystackTransaction, parseVerificationResponse, PAYSTACK_VERIFY_URL } from '../../src/domain/verification.js';
import type { ModelRecord } from '../../src/storage/schema.js';
import { isDueIntent, runPaystackReconciliationTick } from '../../src/storage/reconciliation.js';

import { NOW, INTENT_ID, ATTEMPT_ID, REFERENCE, SECRET, createVerificationFixture as createFixture, successData } from '../support/verification-fixture.js';

describe('Paystack verification implementation', () => {
	it('verifies only the persisted reference and atomically stores the paid receipt and stable pending result', async () => {
		const fixture = await createFixture();
		const result = await verifyPaystackTransaction({ intentId: INTENT_ID }, fixture.dependencies);

		expect(result.kind).toBe('paid');
		expect(fixture.fetches).toHaveLength(1);
		expect(fixture.fetches[0]?.url).toBe(`${PAYSTACK_VERIFY_URL}${encodeURIComponent(REFERENCE)}`);
		expect(fixture.fetches[0]?.init).toMatchObject({ method: 'GET', redirect: 'manual', headers: {
			accept: 'application/json', authorization: `Bearer ${SECRET}`,
		} });
		expect(fixture.intents.writeCount).toBe(1);
		expect(fixture.intents.value).toMatchObject({
			state: 'verified_paid', deliveryState: 'pending', verificationState: 'matched',
			receipt: { provider: 'paystack', status: 'success', providerResourceId: '4099260516', providerReference: REFERENCE,
				amount: { currency: 'NGN', value: '5000.00' }, domain: 'test', channel: 'card' },
			resultEvent: { schemaVersion: '1.0', type: 'payment.verified', intentId: INTENT_ID,
				amount: { currency: 'NGN', value: '5000.00' }, providerResourceId: '4099260516', providerReference: REFERENCE },
			providerObservation: { providerCustomerId: '1001' },
		});
		expect(fixture.intents.value?.resultEventId).toBe(fixture.intents.value?.resultEvent &&
			(fixture.intents.value.resultEvent as { eventId: string }).eventId);
		expect(JSON.stringify(fixture.intents.value)).not.toContain('payer@example.test');
	});

	it.each([
		['wrong reference', { reference: 'psk-other-reference' }],
		['wrong provider domain', { domain: 'live' }],
		['wrong amount', { amount: 500001 }],
		['wrong requested amount', { requested_amount: 499999 }],
		['wrong currency', { currency: 'USD' }],
		['wrong customer association', { customer: { id: 1001, email: 'someone-else@example.test' } }],
		['wrong channel', { channel: 'bank' }],
	])('holds a successful provider response for review on %s', async (_name, patch) => {
		const fixture = await createFixture({ provider: { ...successData(), ...patch } });
		const result = await verifyPaystackTransaction({ intentId: INTENT_ID }, fixture.dependencies);
		expect(result.kind).toBe('review_required');
		expect(fixture.intents.value).toMatchObject({ state: 'review_required', verificationState: 'mismatch', deliveryState: 'not_eligible' });
		expect(fixture.intents.value).not.toHaveProperty('resultEvent');
		expect(fixture.intents.writeCount).toBe(1);
	});

	it('accepts Paystack fee pass-through only when the provider gross reconciles to the protected price', async () => {
		const fixture = await createFixture({ provider: { ...successData(), amount: 517767, fees: 17767 } });
		const result = await verifyPaystackTransaction({ intentId: INTENT_ID }, fixture.dependencies);
		expect(result.kind).toBe('paid');
		expect(fixture.intents.value).toMatchObject({ state: 'verified_paid', receipt: { amount: { value: '5000.00' } },
			providerObservation: { amountMinor: '517767', requestedAmountMinor: '500000', feesMinor: '17767' } });
	});

	it('holds a fee-pass-through response when the gross charge and Paystack fee do not reconcile', async () => {
		const fixture = await createFixture({ provider: { ...successData(), amount: 517767, fees: 17766 } });
		const result = await verifyPaystackTransaction({ intentId: INTENT_ID }, fixture.dependencies);
		expect(result.kind).toBe('review_required');
		expect(fixture.intents.value).toMatchObject({ state: 'review_required', verificationState: 'mismatch' });
		expect(fixture.intents.value).not.toHaveProperty('resultEvent');
	});

	it('does not classify failed as final before provider finality proof and keeps the reference for read-only recovery', async () => {
		const fixture = await createFixture({ provider: { ...successData(), status: 'failed' } });
		const result = await verifyPaystackTransaction({ intentId: INTENT_ID }, fixture.dependencies);
		expect(result.kind).toBe('pending');
		expect(fixture.intents.value).toMatchObject({ state: 'unknown', attempts: [{
			state: 'unknown', providerState: 'failed', providerReference: REFERENCE, verificationCount: 1,
		}] });
		expect(fixture.intents.value).not.toHaveProperty('receipt');
		expect(fixture.intents.value).not.toHaveProperty('resultEvent');
		expect(fixture.intents.value?.providerObservation).not.toHaveProperty('providerCustomerId');
	});

	it('keeps the original checkout link while a scheduled verification remains pending', async () => {
		const fixture = await createFixture({ provider: { ...successData(), status: 'pending' } });
		const original = fixture.intents.value!;
		const attempts = original.attempts as Array<Record<string, unknown>>;
		const action = { id: ATTEMPT_ID, kind: 'redirect', destination: 'https://checkout.paystack.com/example' };
		fixture.intents.value = { ...original, state: 'requires_action', attempts: [{ ...attempts[0], state: 'requires_action',
			providerState: 'initialized', nextAction: action }] };
		expect(isDueIntent(INTENT_ID, fixture.intents.value, NOW)).toBe(true);
		expect((await verifyPaystackTransaction({ intentId: INTENT_ID }, fixture.dependencies)).kind).toBe('pending');
		expect(fixture.intents.value).toMatchObject({ state: 'requires_action', nextRunAt: NOW + 60_000,
			attempts: [{ state: 'requires_action', nextAction: action, verificationCount: 1, nextRunAt: NOW + 60_000 }] });
		expect(isDueIntent(INTENT_ID, fixture.intents.value!, NOW)).toBe(false);
	});

	it('confirms a successful checkout without relying on a webhook', async () => {
		const fixture = await createFixture();
		const original = fixture.intents.value!;
		const attempts = original.attempts as Array<Record<string, unknown>>;
		fixture.intents.value = { ...original, state: 'requires_action', attempts: [{ ...attempts[0], state: 'requires_action',
			providerState: 'initialized', nextAction: { id: ATTEMPT_ID, kind: 'redirect', destination: 'https://checkout.paystack.com/example' } }] };
		expect(isDueIntent(INTENT_ID, fixture.intents.value, NOW)).toBe(true);
		expect((await verifyPaystackTransaction({ intentId: INTENT_ID }, fixture.dependencies)).kind).toBe('paid');
		expect(fixture.intents.value).toMatchObject({ state: 'verified_paid', deliveryState: 'pending', receipt: { status: 'success' } });
	});

	it('scheduler selects and verifies an initialized checkout without a webhook', async () => {
		vi.useFakeTimers(); vi.setSystemTime(NOW);
		try {
			const fixture = await createFixture(); const initial = fixture.intents.value!;
			const attempts = initial.attempts as Array<Record<string, unknown>>;
			fixture.intents.value = { ...initial, state: 'requires_action', attempts: [{ ...attempts[0], state: 'requires_action',
				providerState: 'initialized', nextAction: { id: ATTEMPT_ID, kind: 'redirect', destination: 'https://checkout.paystack.com/example' } }] };
			fixture.intents.query = async (options) => {
				const filter = options?.where?.state as { in?: string[] };
				return { items: filter?.in?.includes('requires_action') && fixture.intents.value ? [{ id: INTENT_ID, data: fixture.intents.value }] : [], hasMore: false };
			};
			let health: ModelRecord | null = null; let revision = 0;
			const budgets = { getVersioned: async () => health ? { value: health, revision: String(revision) } : null,
				compareAndSet: async (_id: string, expected: string | null, value: ModelRecord) => {
					if (expected !== (health ? String(revision) : null)) return { applied: false as const };
					health = value; return { applied: true as const, revision: String(++revision) };
				} };
			const ctx = { plugin: { id: fixture.dependencies.pluginId }, settings: fixture.dependencies.settings,
				storage: { intents: fixture.intents, budgets }, http: { fetch: fixture.dependencies.fetch } } as unknown as PluginContext;
			await runPaystackReconciliationTick({ name: 'reconcile' } as any, ctx);
			expect(fixture.intents.value).toMatchObject({ state: 'verified_paid', receipt: { status: 'success' } });
			expect(fixture.fetches).toHaveLength(1);
		} finally { vi.useRealTimers(); }
	});

	it('does not refresh scheduler health when processing throws after selection', async () => {
		vi.useFakeTimers(); vi.setSystemTime(NOW);
		try {
			const fixture = await createFixture();
			fixture.intents.query = async () => ({
				items: [{ id: INTENT_ID, data: fixture.intents.value! }], hasMore: false,
			});
			let health: ModelRecord | null = null;
			let revision = 0;
			const budgets = {
				getVersioned: async () => health ? { value: health, revision: String(revision) } : null,
				compareAndSet: async (_id: string, expected: string | null, value: ModelRecord) => {
					if (expected !== (health ? String(revision) : null)) return { applied: false as const };
					health = value;
					return { applied: true as const, revision: String(++revision) };
				},
			};
			const ctx = {
				get plugin() { throw new Error('host bridge failed'); },
				settings: fixture.dependencies.settings,
				storage: { intents: fixture.intents, budgets },
				http: { fetch: fixture.dependencies.fetch },
			} as unknown as PluginContext;
			await runPaystackReconciliationTick({ name: 'reconcile' } as any, ctx);
			expect(health).toMatchObject({ lastSuccessfulAt: null, nextQueue: 'intents', lease: null });
		} finally { vi.useRealTimers(); }
	});

	it('does not exceed the approved eight provider verification reads', async () => {
		const fixture = await createFixture({ verificationCount: 8, initialState: 'unknown' });
		const result = await verifyPaystackTransaction({ intentId: INTENT_ID }, fixture.dependencies);
		expect(result.kind).toBe('review_required');
		expect(fixture.fetches).toHaveLength(0);
		expect(fixture.intents.value).toMatchObject({ state: 'review_required', attempts: [{ verificationCount: 8 }] });
	});

	it('records reversal separately while preserving the verified receipt and stable result', async () => {
		const fixture = await createFixture({ initialState: 'verified_paid', priorPaid: true, provider: { ...successData(), status: 'reversed' } });
		const result = await verifyPaystackTransaction({ intentId: INTENT_ID, attemptId: ATTEMPT_ID, forceVerification: true }, fixture.dependencies);
		expect(result.kind).toBe('already_paid');
		expect(fixture.intents.value).toMatchObject({
			state: 'verified_paid', deliveryState: 'pending',
			financialObservations: [{ kind: 'reversal', status: 'reversed', providerReference: REFERENCE }],
		});
		expect(fixture.intents.value?.receipt).toEqual(fixture.priorReceipt);
		expect(fixture.intents.value?.resultEvent).toEqual(fixture.priorResult);
	});

	it('confirms an applied paid CAS after the storage bridge loses its response', async () => {
		const fixture = await createFixture({ failAfterApply: true });
		const result = await verifyPaystackTransaction({ intentId: INTENT_ID }, fixture.dependencies);
		expect(result.kind).toBe('paid');
		expect(fixture.intents.writeCount).toBe(1);
		expect(fixture.intents.value).toMatchObject({ state: 'verified_paid', deliveryState: 'pending', receipt: { status: 'success' } });
	});

	it('does not let an old failed verification CAS overwrite a concurrent paid transition', async () => {
		const fixture = await createFixture({ provider: { ...successData(), status: 'failed' },
			beforeCas: async (store) => { store.value = { ...store.value!, state: 'verified_paid', deliveryState: 'pending', resultEventId: 'psk:v1:results:' + 'a'.repeat(64) }; store.revision = 'concurrent-paid'; } });
		const result = await verifyPaystackTransaction({ intentId: INTENT_ID }, fixture.dependencies);
		expect(result.kind).toBe('conflict');
		expect(fixture.intents.value?.state).toBe('verified_paid');
		expect((fixture.intents.value as { attempts: Array<{ providerState: string }> } | null)?.attempts[0]?.providerState).toBe('create_started');
	});

	it('marks provider vocabulary not in the allowlist for review without persisting the provider string', async () => {
		const fixture = await createFixture({ provider: { ...successData(), status: 'awaiting_settlement_with_details' } });
		const result = await verifyPaystackTransaction({ intentId: INTENT_ID }, fixture.dependencies);
		expect(result.kind).toBe('review_required');
		expect(JSON.stringify(fixture.intents.value)).not.toContain('awaiting_settlement_with_details');
		expect(fixture.intents.value).toMatchObject({ state: 'review_required', providerObservation: { status: 'unknown_provider_status' } });
	});

	it('parses large numeric provider IDs losslessly and rejects non-200/redirected responses', async () => {
		const response = new Response(`{"status":true,"data":{"id":9007199254740993,"domain":"test","status":"success","reference":"${REFERENCE}","amount":500000,"currency":"NGN","channel":"card","customer":{"id":1001,"email":"payer@example.test"}}}`, {
			status: 200, headers: { 'content-type': 'application/json' },
		});
		const parsed = await parseVerificationResponse(response, REFERENCE);
		expect(parsed).toMatchObject({ kind: 'valid', value: { resourceId: '9007199254740993', customerId: '1001' } });
		expect(await parseVerificationResponse(new Response('{}', { status: 404 }), REFERENCE)).toEqual({ kind: 'unavailable' });
	});
});
