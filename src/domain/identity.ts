import { hmacIndex, type IndexHmacKey } from '../security/encryption.js';
import { isPlainObject, StorageInvariantError } from '../storage/schema.js';

export interface IntentIdentityInput {
	readonly siteId: string;
	readonly subject: { readonly kind: string; readonly id: string };
	readonly merchantId: string;
	readonly environment: 'test' | 'live';
	readonly businessReference: string;
}

export interface IntentFingerprintInput {
	readonly formId: string;
	readonly formRevision: string;
	readonly pricingMode: 'fixed' | 'trusted_order' | 'payer_entered';
	readonly amountMinor: string;
	readonly fields: Readonly<Record<string, unknown>>;
	readonly metadata: Readonly<Record<string, unknown>>;
	readonly method: 'card';
	readonly returnPolicy: string;
}

export async function deriveIntentIdentity(input: IntentIdentityInput, key: IndexHmacKey): Promise<string> {
	const fields = [
		'paystack-intent-v1',
		validateIdentityPart(input.siteId, 'siteId'),
		validateIdentityPart(input.subject.kind, 'subject.kind'),
		validateIdentityPart(input.subject.id, 'subject.id'),
		validateIdentityPart(input.merchantId, 'merchantId'),
		validateEnvironment(input.environment),
		validateIdentityPart(input.businessReference, 'businessReference'),
	];
	return hmacIndex(fields, key);
}

export async function deriveRequestKeyId(siteId: string, requestKey: string, key: IndexHmacKey): Promise<string> {
	return hmacIndex(
		['paystack-request-key-v1', validateIdentityPart(siteId, 'siteId'), validateIdentityPart(requestKey, 'requestKey')],
		key,
	);
}

export async function deriveIntentFingerprint(input: IntentFingerprintInput, key: IndexHmacKey): Promise<string> {
	if (!input || !isPlainObject(input.fields) || !isPlainObject(input.metadata)) {
		throw new StorageInvariantError('INVALID_FINGERPRINT');
	}
	const canonical = canonicalJson({
		formId: input.formId,
		formRevision: input.formRevision,
		pricingMode: input.pricingMode,
		amountMinor: input.amountMinor,
		fields: input.fields,
		metadata: input.metadata,
		method: input.method,
		returnPolicy: input.returnPolicy,
	});
	return hmacIndex(['paystack-fingerprint-v1', canonical], key);
}

export function canonicalJson(value: unknown): string {
	if (value === null) return 'null';
	if (typeof value === 'string') return JSON.stringify(value);
	if (typeof value === 'boolean') return value ? 'true' : 'false';
	if (typeof value === 'number') {
		if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
			throw new StorageInvariantError('UNSAFE_NUMBER');
		}
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
	if (!isPlainObject(value)) throw new StorageInvariantError('INVALID_CANONICAL_VALUE');
	const entries = Object.keys(value).sort().map((key) => {
		if (isReservedKey(key)) throw new StorageInvariantError('RESERVED_KEY');
		return `${JSON.stringify(key)}:${canonicalJson(value[key])}`;
	});
	return `{${entries.join(',')}}`;
}

function validateIdentityPart(value: string, name: string): string {
	if (
		typeof value !== 'string' ||
		value.length < 1 ||
		new TextEncoder().encode(value).byteLength > 1024 ||
		/[\u0000-\u001f\u007f]/u.test(value)
	) {
		throw new StorageInvariantError(`INVALID_${name.replaceAll('.', '_').toUpperCase()}`);
	}
	return value;
}

function validateEnvironment(value: string): string {
	if (value !== 'test' && value !== 'live') throw new StorageInvariantError('INVALID_ENVIRONMENT');
	return value;
}

function isReservedKey(key: string): boolean {
	return key === '__proto__' || key === 'prototype' || key === 'constructor';
}
