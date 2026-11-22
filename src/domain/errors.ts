export const SAFE_ERROR_CODES = [
	'protected_field_override',
	'intent_conflict',
	'request_key_conflict',
	'retry_not_allowed',
	'validation_error',
	'unsupported_schema',
	'unsupported_method',
	'form_unavailable',
	'stale_revision',
	'unauthorized',
	'forbidden',
	'rate_limited',
	'provider_unavailable',
	'storage_unavailable',
	'invalid_signature',
	'review_required',
] as const;

export type SafeErrorCode = (typeof SAFE_ERROR_CODES)[number];

export interface SafeError {
	readonly code: SafeErrorCode;
	readonly message: string;
}

const SAFE_MESSAGES: Readonly<Record<SafeErrorCode, string>> = Object.freeze({
	protected_field_override: 'Protected payment fields cannot be changed by the payer.',
	intent_conflict: 'This payment intent conflicts with an existing request.',
	request_key_conflict: 'This request key is already bound to a different payment attempt.',
	retry_not_allowed: 'This payment cannot be retried in its current state.',
	validation_error: 'The request could not be validated.',
	unsupported_schema: 'This form version is not supported.',
	unsupported_method: 'This payment method is not supported.',
	form_unavailable: 'This payment form is unavailable.',
	stale_revision: 'The saved version has changed. Reload and try again.',
	unauthorized: 'The request could not be authenticated.',
	forbidden: 'The request is not permitted.',
	rate_limited: 'Too many requests. Try again later.',
	provider_unavailable: 'Payment processing is temporarily unavailable.',
	storage_unavailable: 'Payment state could not be safely saved.',
	invalid_signature: 'The request signature is invalid.',
	review_required: 'This payment needs review before it can continue.',
});

const SOURCE_ALIASES: Readonly<Record<string, SafeErrorCode>> = Object.freeze({
	unsupported_action: 'review_required',
	temporary_unavailable: 'provider_unavailable',
	capacity_exceeded: 'review_required',
});

export function isSafeErrorCode(value: unknown): value is SafeErrorCode {
	return typeof value === 'string' && (SAFE_ERROR_CODES as readonly string[]).includes(value);
}

export function isKnownSourceErrorCode(value: unknown): boolean {
	return isSafeErrorCode(value) || (typeof value === 'string' && Object.hasOwn(SOURCE_ALIASES, value));
}

export function mapSafeErrorCode(value: unknown): SafeErrorCode {
	if (isSafeErrorCode(value)) return value;
	if (typeof value === 'string' && Object.hasOwn(SOURCE_ALIASES, value)) return SOURCE_ALIASES[value]!;
	return 'provider_unavailable';
}

export function safeError(code: SafeErrorCode): SafeError {
	return Object.freeze({ code, message: SAFE_MESSAGES[code] });
}
