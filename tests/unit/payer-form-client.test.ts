import { describe, expect, it } from 'vite-plus/test';
import {
	buildSubmission,
	buildCreatedPaymentAction,
	buildRecoveryRequest,
	clearRequestKey,
	clearRecoveryDraft,
	getOrCreateRequestKey,
	parseSitePaymentStatus,
	readRecoveryDraft,
	safeCheckoutDestination,
	saveRecoveryDraft,
	validateEnterAmount,
	type PublicFormField,
} from '../../examples/astro-site/payer-form/client.js';

const intentId = `psk:v1:intents:${'a'.repeat(64)}`;
const attemptId = `psk:v1:attempts:${'b'.repeat(64)}`;

const fields: readonly PublicFormField[] = [
	{ id: 'payer_email', type: 'email', label: 'Email', required: true },
	{ id: 'message', type: 'textarea', label: 'Message' },
];

describe('payer-form site renderer support', () => {
	it('accepts only bounded NGN Enter amount values at two-decimal precision', () => {
		expect(validateEnterAmount('50.00', '50.00', '1000000.00')).toBe(true);
		expect(validateEnterAmount('1000000', '50', '1000000')).toBe(true);
		expect(validateEnterAmount('49.99', '50.00', '1000000.00')).toBe(false);
		expect(validateEnterAmount('1000000.01', '50.00', '1000000.00')).toBe(false);
		expect(validateEnterAmount('1e3', '50.00', '1000000.00')).toBe(false);
		expect(validateEnterAmount('50.001', '50.00', '1000000.00')).toBe(false);
	});

	it('serializes only declared custom fields and adds payerAmount only for Enter amount pricing', () => {
		const submission = buildSubmission({
			formId: 'service_payment', formRevision: 'revision_1', requestKey: '550e8400-e29b-41d4-a716-446655440000',
			fields, values: {
				payer_email: 'payer@example.test', message: 'Consulting fee', payerAmount: '2500.00',
				amount: '0.01', currency: 'USD', siteId: 'forged-site',
			},
			pricing: { mode: 'payer_entered', currency: 'NGN', minimum: '50.00', maximum: '1000000.00', fractionDigits: 2 },
		});
		expect(submission).toEqual({
			schemaVersion: '1.0', formId: 'service_payment', formRevision: 'revision_1',
			requestKey: '550e8400-e29b-41d4-a716-446655440000',
			fields: { payer_email: 'payer@example.test', message: 'Consulting fee' }, payerAmount: '2500.00',
		});
		expect(buildSubmission({
			formId: 'service_payment', formRevision: 'revision_1', requestKey: '550e8400-e29b-41d4-a716-446655440000',
			fields, values: { payer_email: 'payer@example.test', payerAmount: '2500.00' },
			pricing: { mode: 'fixed', currency: 'NGN', amount: '2500.00' },
		})).toBeNull();
	});

	it('stores one request key and a short-lived recovery draft for reload reconciliation', () => {
		const storage = new MemoryStorage();
		const first = getOrCreateRequestKey(storage, 'service_payment', 'revision_1', () => '550e8400-e29b-41d4-a716-446655440000');
		const afterReload = getOrCreateRequestKey(storage, 'service_payment', 'revision_1', () => '00000000-0000-4000-8000-000000000000');
		expect(first).toEqual({ requestKey: '550e8400-e29b-41d4-a716-446655440000', persisted: true });
		expect(afterReload.requestKey).toBe(first.requestKey);
		clearRequestKey(storage, 'service_payment', 'revision_1');
		expect(getOrCreateRequestKey(storage, 'service_payment', 'revision_1', () => '00000000-0000-4000-8000-000000000000').requestKey)
			.toBe('00000000-0000-4000-8000-000000000000');
		const submission = buildSubmission({
			formId: 'service_payment', formRevision: 'revision_1', requestKey: first.requestKey, fields,
			values: { payer_email: 'payer@example.test', message: 'Consulting fee', payerAmount: '2500.00' },
			pricing: { mode: 'payer_entered', currency: 'NGN', minimum: '50.00', maximum: '1000000.00', fractionDigits: 2 },
		});
		expect(submission).not.toBeNull();
		expect(saveRecoveryDraft(storage, submission!, 1_000)).toBe(true);
		expect(readRecoveryDraft(storage, 'service_payment', 'revision_1', 2_000)?.submission).toEqual(submission);
		expect(readRecoveryDraft(storage, 'service_payment', 'revision_1', 1_000 + 30 * 60 * 1000 + 1)).toBeNull();
		clearRecoveryDraft(storage, 'service_payment', 'revision_1');
		expect(readRecoveryDraft(storage, 'service_payment', 'revision_1', 2_000)).toBeNull();
	});

	it('replays only the identical request key until an intent is known, then sends an owned status query', () => {
		const storage = new MemoryStorage();
		const submission = buildSubmission({
			formId: 'service_payment', formRevision: 'revision_1', requestKey: '550e8400-e29b-41d4-a716-446655440000', fields,
			values: { payer_email: 'payer@example.test', message: 'Consulting fee', payerAmount: '2500.00' },
			pricing: { mode: 'payer_entered', currency: 'NGN', minimum: '50.00', maximum: '1000000.00', fractionDigits: 2 },
		});
		expect(submission).not.toBeNull();
		const baseDraft = { version: 1 as const, savedAt: 10, submission: submission! };
		expect(buildRecoveryRequest(baseDraft)).toEqual({ operation: 'submit', body: submission });
		expect(buildRecoveryRequest({ ...baseDraft, intentId })).toEqual({ operation: 'submit', body: submission });
		expect(saveRecoveryDraft(storage, submission!, 10, { intentId: intentId, attemptId: attemptId })).toBe(true);
		const recovered = readRecoveryDraft(storage, 'service_payment', 'revision_1', 11);
		expect(recovered).toMatchObject({ intentId: intentId, attemptId: attemptId });
		expect(buildRecoveryRequest(recovered!)).toEqual({
			operation: 'status', body: { schemaVersion: '1.0', intentId: intentId, attemptId: attemptId },
		});
		expect(JSON.stringify(buildRecoveryRequest(recovered!))).not.toContain('payer@example.test');
		expect(JSON.stringify(buildRecoveryRequest(recovered!))).not.toContain('requestKey');
	});

	it('only accepts the exact secure Paystack checkout origin as a next action', () => {
		expect(safeCheckoutDestination('https://checkout.paystack.com/abc')).toBe('https://checkout.paystack.com/abc');
		expect(safeCheckoutDestination('https://checkout.paystack.com.evil.test/abc')).toBeNull();
		expect(safeCheckoutDestination('http://checkout.paystack.com/abc')).toBeNull();
		expect(safeCheckoutDestination('javascript:alert(1)')).toBeNull();
	});

	it('accepts only versioned owned payment states and allowlisted hosted-card redirects', () => {
		const status = {
			schemaVersion: '1.0', intentId: intentId, attemptId: attemptId, state: 'requires_action',
			deliveryState: 'not_eligible', nextAction: {
				id: attemptId, kind: 'redirect', destination: 'https://checkout.paystack.com/abc',
			},
		};
		expect(parseSitePaymentStatus(status)).toEqual(status);
		expect(parseSitePaymentStatus({ success: true, data: { ok: true, value: status } })).toEqual(status);
		expect(parseSitePaymentStatus({ success: true, data: { ok: false, error: { code: 'provider_unavailable' } } })).toBeNull();
		expect(parseSitePaymentStatus({ ...status, schemaVersion: '2.0' })).toBeNull();
		expect(parseSitePaymentStatus({ ...status, intentId: '../other' })).toBeNull();
		expect(parseSitePaymentStatus({ ...status, nextAction: { ...status.nextAction, destination: 'https://checkout.paystack.com.evil.test/abc' } })).toBeNull();
		expect(parseSitePaymentStatus({ ...status, nextAction: { ...status.nextAction, id: `psk:v1:attempts:${'c'.repeat(64)}` } })).toBeNull();
	});

	it('starts only the exact server-created attempt and never starts an unresolved attempt again', () => {
		const status = { schemaVersion: '1.0', intentId, attemptId, state: 'created', deliveryState: 'not_eligible' };
		expect(buildCreatedPaymentAction(status)).toEqual({ schemaVersion: '1.0', intentId, attemptId, actionId: attemptId });
		for (const state of ['initializing', 'unknown', 'pending', 'verified_paid', 'requires_action']) {
			expect(buildCreatedPaymentAction({ ...status, state })).toBeNull();
		}
		expect(buildCreatedPaymentAction({ ...status, attemptId: 'attempt_456' })).toBeNull();
	});
});

class MemoryStorage implements Pick<Storage, 'getItem' | 'setItem' | 'removeItem'> {
	readonly #values = new Map<string, string>();
	getItem(key: string): string | null { return this.#values.get(key) ?? null; }
	setItem(key: string, value: string): void { this.#values.set(key, value); }
	removeItem(key: string): void { this.#values.delete(key); }
}
