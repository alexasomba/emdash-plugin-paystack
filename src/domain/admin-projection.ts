import { isSafeErrorCode, type SafeErrorCode } from './errors.js';
import { isPlainObject } from '../storage/schema.js';

export type AdminProjection = Readonly<Record<string, unknown>>;

const ENVIRONMENTS = ['test', 'live'] as const;
const MONEY_STATES = ['unpaid', 'verified_paid', 'review_required'] as const;
const ATTEMPT_STATES = ['created', 'initializing', 'requires_action', 'pending', 'succeeded', 'failed', 'canceled', 'review_required'] as const;
const DELIVERY_STATES = ['not_eligible', 'pending', 'acknowledged'] as const;
const VERIFICATION_STATES = ['unverified', 'matched', 'mismatch', 'late_success'] as const;
const AUTHENTICITY_STATES = ['verified', 'rejected'] as const;
const PROCESSING_STATES = ['pending', 'processing', 'completed', 'duplicate', 'rejected', 'failed'] as const;
const MAX_HISTORY = 10;

/** Build a customer view from trusted, already-decrypted fields. Never trust a pre-masked field. */
export function projectAdminCustomer(value: unknown): AdminProjection | null {
	if (!isPlainObject(value)) return null;
	const output: Record<string, unknown> = {};
	copyOpaqueId(value, output, 'customerCorrelationId');
	copyOpaqueId(value, output, 'subjectCorrelationId');
	copyOpaqueId(value, output, 'providerCustomerCorrelationId');
	copyOpaqueId(value, output, 'merchantProfileId');
	copyEnum(value, output, 'environment', ENVIRONMENTS);
	copyEnum(value, output, 'mappingState', ['mapped', 'unmapped', 'error'] as const);
	copyTimestamp(value, output, 'createdAt');
	copyTimestamp(value, output, 'updatedAt');
	const maskedEmail = maskEmail(value.email);
	if (maskedEmail) output.maskedEmail = maskedEmail;
	return Object.freeze(output);
}

/** Construct the ordinary payment row from an allowlist; raw provider values are never copied. */
export function projectAdminPayment(value: unknown): AdminProjection | null {
	if (!isPlainObject(value)) return null;
	const output = paymentBase(value);
	copyTimestamp(value, output, 'verifiedAt');
	return Object.freeze(output);
}

/** Construct detail fields independently, including a bounded nested history allowlist. */
export function projectAdminPaymentDetail(value: unknown): AdminProjection | null {
	if (!isPlainObject(value)) return null;
	const output = paymentBase(value);
	copyTimestamp(value, output, 'verifiedAt');
	copyOpaqueId(value, output, 'providerResourceCorrelationId');
	copyOpaqueId(value, output, 'providerReferenceCorrelationId');
	copyOpaqueId(value, output, 'resultEventId');
	copyMoney(value, output, 'providerAmount');
	copyEnum(value, output, 'verificationState', VERIFICATION_STATES);
	const maskedEmail = maskEmail(value.email);
	if (maskedEmail) output.maskedEmail = maskedEmail;
	if (Array.isArray(value.history)) {
		const history = value.history.slice(0, MAX_HISTORY).flatMap((candidate) => {
			if (!isPlainObject(candidate)) return [];
			const entry: Record<string, unknown> = {};
			copyOpaqueId(candidate, entry, 'attemptId');
			copyEnum(candidate, entry, 'state', ATTEMPT_STATES);
			copyTimestamp(candidate, entry, 'occurredAt');
			copyErrorCode(candidate, entry, 'failureCode');
			return Object.keys(entry).length > 0 ? [Object.freeze(entry)] : [];
		});
		output.history = Object.freeze(history);
	}
	return Object.freeze(output);
}

/** Construct a webhook row without accepting a raw event body or provider identifiers. */
export function projectAdminWebhookEvent(value: unknown): AdminProjection | null {
	if (!isPlainObject(value)) return null;
	const output: Record<string, unknown> = {};
	copyOpaqueId(value, output, 'eventId');
	copyOpaqueId(value, output, 'paymentId');
	copyOpaqueId(value, output, 'attemptId');
	copyOpaqueId(value, output, 'providerEventCorrelationId');
	copyOpaqueId(value, output, 'merchantProfileId');
	copyEnum(value, output, 'environment', ENVIRONMENTS);
	copyEnum(value, output, 'authenticityState', AUTHENTICITY_STATES);
	copyEnum(value, output, 'processingState', PROCESSING_STATES);
	copyTimestamp(value, output, 'receivedAt');
	copyTimestamp(value, output, 'processedAt');
	copyErrorCode(value, output, 'failureCode');
	return Object.freeze(output);
}

/** The only customer-data projection: valid ASCII addresses become a fixed-width mask. */
export function maskEmail(value: unknown): string | undefined {
	if (typeof value !== 'string' || value.length > 254 || !isValidEmail(value)) return undefined;
	const local = value.slice(0, value.lastIndexOf('@'));
	const first = /^[a-z0-9]/iu.test(local) ? local[0]!.toLowerCase() : '•';
	return `${first}••••@••••`;
}

function paymentBase(value: Record<string, unknown>): Record<string, unknown> {
	const output: Record<string, unknown> = {};
	for (const key of ['paymentId', 'intentId', 'attemptId', 'customerCorrelationId', 'merchantProfileId'] as const) {
		copyOpaqueId(value, output, key);
	}
	copyEnum(value, output, 'environment', ENVIRONMENTS);
	copyOpaqueId(value, output, 'formId');
	copyOpaqueId(value, output, 'formRevision');
	copyMoney(value, output, 'expectedAmount');
	copyEnum(value, output, 'moneyState', MONEY_STATES);
	copyEnum(value, output, 'attemptState', ATTEMPT_STATES);
	copyEnum(value, output, 'deliveryState', DELIVERY_STATES);
	copyTimestamp(value, output, 'createdAt');
	copyTimestamp(value, output, 'updatedAt');
	return output;
}

function copyOpaqueId(source: Record<string, unknown>, target: Record<string, unknown>, key: string): void {
	const value = source[key];
	if (typeof value === 'string' && value.length <= 200 && /^[A-Za-z0-9_:-]{1,200}$/u.test(value)) target[key] = value;
}

function copyEnum<const T extends readonly string[]>(source: Record<string, unknown>, target: Record<string, unknown>, key: string, values: T): void {
	const value = source[key];
	if (typeof value === 'string') target[key] = (values as readonly string[]).includes(value) ? value : 'unknown';
}

function copyTimestamp(source: Record<string, unknown>, target: Record<string, unknown>, key: string): void {
	const value = source[key];
	if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/u.test(value)) return;
	const ms = Date.parse(value);
	if (Number.isFinite(ms)) target[key] = value;
}

function copyMoney(source: Record<string, unknown>, target: Record<string, unknown>, key: string): void {
	const value = source[key];
	if (!isPlainObject(value) || value.currency !== 'NGN' || typeof value.value !== 'string' ||
		!/^[1-9][0-9]*\.[0-9]{2}$/u.test(value.value) || value.value.length > 32) return;
	target[key] = Object.freeze({ currency: 'NGN', value: value.value });
}

function copyErrorCode(source: Record<string, unknown>, target: Record<string, unknown>, key: string): void {
	const value = source[key];
	if (typeof value !== 'string') return;
	target[key] = isSafeErrorCode(value) ? value : 'unknown';
}

function isValidEmail(value: string): boolean {
	if (!/^[\x21-\x7e]+$/u.test(value) || /\s/u.test(value)) return false;
	const at = value.lastIndexOf('@');
	if (at < 1 || at !== value.indexOf('@') || at > 64 || value.length - at - 1 > 253) return false;
	const local = value.slice(0, at);
	const domain = value.slice(at + 1);
	if (local.startsWith('.') || local.endsWith('.') || local.includes('..') ||
		!/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/u.test(local)) return false;
	const labels = domain.split('.');
	return labels.length >= 2 && labels.every((label) => label.length >= 1 && label.length <= 63 &&
		/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(label));
}

export type AdminFailureCode = SafeErrorCode | 'unknown';
