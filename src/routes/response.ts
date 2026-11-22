import { isKnownSourceErrorCode, mapSafeErrorCode, safeError, type SafeError, type SafeErrorCode } from '../domain/errors.js';

export type DomainResult<T> =
	| { readonly ok: true; readonly value: T }
	| { readonly ok: false; readonly error: SafeError };

export interface HostEnvelope<T> {
	readonly success: true;
	readonly data: DomainResult<T>;
}

export interface RawHostExecution {
	readonly success: boolean;
	readonly data?: unknown;
	readonly error?: unknown;
	readonly status?: unknown;
}

export function domainOk<T>(value: T): DomainResult<T> {
	return Object.freeze({ ok: true, value });
}

export function domainError(code: SafeErrorCode): DomainResult<never> {
	return Object.freeze({ ok: false, error: safeError(code) });
}

/** Normal EmDash JSON routes wrap the domain result; success only describes route execution. */
export function toHostEnvelope<T>(result: DomainResult<T>): HostEnvelope<T> {
	return Object.freeze({ success: true, data: normalizeDomainResult(result) as DomainResult<T> });
}

/** Raw runtime invocation returns an execution wrapper, whose data is the domain result. */
export function fromRawHostExecution(raw: unknown): DomainResult<unknown> {
	if (!isRecord(raw) || raw.success !== true || !Object.hasOwn(raw, 'data') ||
		(raw.status !== undefined && raw.status !== 200)) {
		return domainError('provider_unavailable');
	}
	const normalized = normalizeUnknownDomain(raw.data);
	return normalized ?? domainError('provider_unavailable');
}

/** Host HTTP JSON is itself an execution envelope; never interpret HTTP 200 as domain success. */
export function fromHostHttpJson(status: number, body: unknown): DomainResult<unknown> {
	if (!Number.isInteger(status) || status !== 200 || !isRecord(body) || body.success !== true || !Object.hasOwn(body, 'data')) {
		return domainError('provider_unavailable');
	}
	return normalizeUnknownDomain(body.data) ?? domainError('provider_unavailable');
}

export function toSiteHttpStatus(result: DomainResult<unknown>): number {
	if (result.ok) return 200;
	switch (result.error.code) {
		case 'unauthorized':
			return 401;
		case 'forbidden':
			return 403;
		case 'validation_error':
		case 'unsupported_schema':
		case 'unsupported_method':
		case 'protected_field_override':
		case 'form_unavailable':
			return 422;
		case 'request_key_conflict':
		case 'intent_conflict':
		case 'retry_not_allowed':
		case 'stale_revision':
		case 'review_required':
			return 409;
		case 'invalid_signature':
			return 401;
		case 'rate_limited':
			return 429;
		case 'provider_unavailable':
		case 'storage_unavailable':
			return 503;
	}
}

function normalizeUnknownDomain(value: unknown): DomainResult<unknown> | null {
	if (!isRecord(value) || typeof value.ok !== 'boolean') return null;
	if (value.ok === true) {
		if (!Object.hasOwn(value, 'value') || Object.hasOwn(value, 'error')) return null;
		return domainOk(value.value);
	}
	if (!Object.hasOwn(value, 'error') || Object.hasOwn(value, 'value') || !isRecord(value.error)) return null;
	const code = value.error.code;
	if (!isKnownSourceErrorCode(code)) return null;
	return domainError(mapSafeErrorCode(code));
}

function normalizeDomainResult<T>(value: DomainResult<T>): DomainResult<T> {
	const normalized = normalizeUnknownDomain(value);
	if (!normalized) return domainError('provider_unavailable');
	return normalized as DomainResult<T>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}
