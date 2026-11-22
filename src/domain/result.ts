import { isPlainObject } from '../storage/schema.js';

export interface VerifiedPaymentResult {
	readonly schemaVersion: '1.0';
	readonly eventId: string;
	readonly type: 'payment.verified';
	readonly paymentId: string;
	readonly intentId: string;
	readonly attemptId: string;
	readonly formId: string;
	readonly formRevision: string;
	readonly provider: 'paystack';
	readonly environment: 'test' | 'live';
	readonly merchantProfile: string;
	readonly amount: { readonly currency: 'NGN'; readonly value: string };
	readonly verifiedAt: string;
	readonly providerResourceId: string;
	readonly providerReference: string;
}

export interface VerifiedResultInput {
	readonly intentId: string;
	readonly attemptId: string;
	readonly formId: string;
	readonly formRevision: string;
	readonly environment: 'test' | 'live';
	readonly merchantProfile: string;
	readonly amount: { readonly currency: 'NGN'; readonly value: string };
	readonly verifiedAt: string;
	readonly providerResourceId: string;
	readonly providerReference: string;
}

/** One stable result identity per business intent, irrespective of delivery or retry attempt. */
export async function createVerifiedPaymentResult(
	input: VerifiedResultInput,
	cryptoProvider: Crypto = globalThis.crypto,
): Promise<VerifiedPaymentResult> {
	if (!isVerifiedResultInput(input)) throw new TypeError('INVALID_VERIFIED_RESULT_INPUT');
	const digest = new Uint8Array(await cryptoProvider.subtle.digest('SHA-256', new TextEncoder().encode(
		`paystack-result-v1\n${input.intentId}`,
	)));
	const eventId = `psk:v1:results:${toHex(digest)}`;
	return Object.freeze({
		schemaVersion: '1.0',
		eventId,
		type: 'payment.verified',
		paymentId: input.intentId,
		intentId: input.intentId,
		attemptId: input.attemptId,
		formId: input.formId,
		formRevision: input.formRevision,
		provider: 'paystack',
		environment: input.environment,
		merchantProfile: input.merchantProfile,
		amount: Object.freeze({ ...input.amount }),
		verifiedAt: input.verifiedAt,
		providerResourceId: input.providerResourceId,
		providerReference: input.providerReference,
	});
}

export function isVerifiedPaymentResult(value: unknown): value is VerifiedPaymentResult {
	return isPlainObject(value) && value.schemaVersion === '1.0' &&
		typeof value.eventId === 'string' && /^psk:v1:results:[a-f0-9]{64}$/u.test(value.eventId) &&
		value.type === 'payment.verified' && typeof value.paymentId === 'string' &&
		typeof value.intentId === 'string' && value.paymentId === value.intentId &&
		typeof value.attemptId === 'string' && typeof value.formId === 'string' &&
		typeof value.formRevision === 'string' && value.provider === 'paystack' &&
		(value.environment === 'test' || value.environment === 'live') &&
		typeof value.merchantProfile === 'string' && isPlainObject(value.amount) &&
		value.amount.currency === 'NGN' && typeof value.amount.value === 'string' &&
	/^[1-9][0-9]*\.[0-9]{2}$/u.test(value.amount.value) &&
		typeof value.verifiedAt === 'string' && Number.isFinite(Date.parse(value.verifiedAt)) &&
		typeof value.providerResourceId === 'string' && /^[1-9][0-9]{0,23}$/u.test(value.providerResourceId) &&
		typeof value.providerReference === 'string' && /^[A-Za-z0-9.=\-]{1,100}$/u.test(value.providerReference);
}

function isVerifiedResultInput(value: unknown): value is VerifiedResultInput {
	if (!isPlainObject(value) || !/^psk:v1:intents:[a-f0-9]{64}$/u.test(String(value.intentId)) ||
		!/^psk:v1:attempts:[a-f0-9]{64}$/u.test(String(value.attemptId)) ||
		typeof value.formId !== 'string' || value.formId.length < 1 || value.formId.length > 120 ||
		typeof value.formRevision !== 'string' || value.formRevision.length < 1 || value.formRevision.length > 255 ||
		(value.environment !== 'test' && value.environment !== 'live') ||
		typeof value.merchantProfile !== 'string' || value.merchantProfile.length < 1 || value.merchantProfile.length > 120 ||
		!isPlainObject(value.amount) || value.amount.currency !== 'NGN' || typeof value.amount.value !== 'string' ||
		!/^[1-9][0-9]*\.[0-9]{2}$/u.test(value.amount.value) ||
		typeof value.verifiedAt !== 'string' || !Number.isFinite(Date.parse(value.verifiedAt)) ||
		typeof value.providerResourceId !== 'string' || !/^[1-9][0-9]{0,23}$/u.test(value.providerResourceId) ||
		typeof value.providerReference !== 'string' || !/^[A-Za-z0-9.=\-]{1,100}$/u.test(value.providerReference)) return false;
	return true;
}

function toHex(value: Uint8Array): string {
	return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
