import { describe, expect, it } from 'vite-plus/test';
import { approvedExamples } from '../support/spec-fixtures.js';
import {
	maskEmail,
	projectAdminCustomer,
	projectAdminPayment,
	projectAdminPaymentDetail,
	projectAdminWebhookEvent,
} from '../../src/domain/admin-projection.js';
import { projectSafeLogRecord } from '../../src/security/logging.js';

describe('admin projections', () => {
	it('constructs every ordinary view from its declared allowlist', () => {
		const examples = approvedExamples.adminProjection.acceptedProjections;
		expect(projectAdminCustomer({ ...examples.customers, email: 'payer@example.test' }))
			.toEqual({ ...examples.customers, maskedEmail: 'p••••@••••' });
		expect(projectAdminPayment(examples.payments)).toEqual(examples.payments);
		expect(projectAdminPaymentDetail({ ...examples['payment-detail'], email: 'payer@example.test' }))
			.toEqual({ ...examples['payment-detail'], maskedEmail: 'p••••@••••' });
		expect(projectAdminWebhookEvent(examples['webhook-events'])).toEqual(examples['webhook-events']);
	});

	it('omits malformed and missing values and never copies source masks or unknown keys', () => {
		expect(projectAdminCustomer({
			customerCorrelationId: 'cc_01',
			environment: 'production',
			mappingState: 'payer@example.test',
			maskedEmail: 'payer@example.test',
			email: 'ü@example.test',
			providerPayload: { email: 'payer@example.test' },
		})).toEqual({ customerCorrelationId: 'cc_01', environment: 'unknown', mappingState: 'unknown' });
		expect(projectAdminPayment({
			paymentId: 'pay_01', moneyState: 'unexpected', attemptState: null,
			expectedAmount: { currency: 'USD', value: '2.00' },
			createdAt: 'not-a-time', reference: 'payer@example.test', resultEvent: { metadata: 'private' },
		})).toEqual({ paymentId: 'pay_01', moneyState: 'unknown' });
	});

	it('bounds nested history and reconstructs only safe fields', () => {
		const base = approvedExamples.adminProjection.acceptedProjections['payment-detail'];
		const history = Array.from({ length: 12 }, (_, index) => ({
			attemptId: `att_${index}`,
			state: index === 0 ? 'payer@example.test' : 'pending',
			occurredAt: '2026-10-17T12:01:00Z',
			failureCode: 'payer@example.test',
			rawPayload: { email: 'payer@example.test' },
		}));
		const projected = projectAdminPaymentDetail({ ...base, history, email: 'payer@example.test' });
		const projectedHistory = projected?.history as readonly Record<string, unknown>[] | undefined;
		expect(projectedHistory).toHaveLength(10);
		expect(projectedHistory?.[0]).toEqual({
			attemptId: 'att_0', state: 'unknown', occurredAt: '2026-10-17T12:01:00Z', failureCode: 'unknown',
		});
		expect(JSON.stringify(projected)).not.toContain('payer@example.test');
		expect(JSON.stringify(projected)).not.toContain('rawPayload');
	});

	it('uses deterministic masking for valid ASCII addresses and omits unsafe addresses', () => {
		for (const example of approvedExamples.adminProjection.maskingCases) {
			expect(maskEmail(example.input)).toBe(example.omitField ? undefined : example.expected);
		}
	});
});

describe('safe log projection', () => {
	it('retains only bounded operational attributes and finite error codes', () => {
		const projected = projectSafeLogRecord({
			event: 'webhook.process',
			outcome: 'ok',
			environment: 'test',
			intentId: `psk:v1:intents:${'a'.repeat(64)}`,
			attemptId: `psk:v1:attempts:${'b'.repeat(64)}`,
			eventId: `psk:v1:inbox:${'c'.repeat(64)}`,
			errorCode: 'invalid_signature',
			durationMs: 250,
			error: 'payer@example.test fixture-secret',
			providerReference: 'private-reference',
			providerPayload: { email: 'payer@example.test' },
		});
		expect(projected).toEqual({
			event: 'webhook.process', outcome: 'ok', environment: 'test',
			intentId: `psk:v1:intents:${'a'.repeat(64)}`, attemptId: `psk:v1:attempts:${'b'.repeat(64)}`,
			eventId: `psk:v1:inbox:${'c'.repeat(64)}`, errorCode: 'invalid_signature', durationMs: 250,
		});
		expect(JSON.stringify(projected)).not.toContain('payer@example.test');
		expect(JSON.stringify(projected)).not.toContain('fixture-secret');
		expect(JSON.stringify(projected)).not.toContain('providerReference');
	});

	it('rejects unknown event names and discards unsafe attributes', () => {
		expect(projectSafeLogRecord({ event: 'private.failure', error: 'secret' })).toBeNull();
		expect(projectSafeLogRecord({ event: 'storage.failure', outcome: 'unexpected', intentId: 'email@example.test', durationMs: Infinity }))
			.toEqual({ event: 'storage.failure', outcome: 'unknown' });
	});
});
