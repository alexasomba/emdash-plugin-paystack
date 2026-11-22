import {
	canonicalJson,
	deriveIntentFingerprint as deriveDetailFingerprint,
	deriveIntentIdentity,
	type IntentIdentityInput,
} from './identity.js';
import {
	MAX_FORM_FIELDS,
	MAX_FORM_FIELD_VALUE_LENGTH,
	MAX_FORM_METADATA_BYTES,
	MAX_FORM_SUBMISSION_BYTES,
} from './forms.js';
import { hmacIndex, type IndexHmacKey } from '../security/encryption.js';
import {
	deterministicRecordId,
	isPlainObject,
	MAX_ATTEMPTS_PER_INTENT,
	StorageInvariantError,
} from '../storage/schema.js';

export type { IntentIdentityInput };

export interface ProtectedIntentFingerprintInput {
	readonly formId: string;
	readonly formRevision: string;
	readonly pricingMode: 'fixed' | 'trusted_order' | 'payer_entered';
	readonly amountMinor: string;
	readonly fields: Readonly<Record<string, string | boolean>>;
	readonly metadata: Readonly<Record<string, string | number | boolean | null>>;
	readonly method: 'card';
	readonly returnPolicy: string;
}

const ATTEMPT_ID = /^psk:v1:attempts:[a-f0-9]{64}$/u;
const INTENT_ID = /^psk:v1:intents:[a-f0-9]{64}$/u;
const FIELD_ID = /^[a-z][a-z0-9_]{0,63}$/u;
const METADATA_KEY = /^[a-z][a-z0-9_-]*\.[A-Za-z0-9_.-]+$/u;
const RESERVED_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const MIN_NGN_MINOR = 5_000n;
const MAX_NGN_MINOR = 100_000_000n;

/** Derive the opaque intent storage ID from the approved stable business identity tuple. */
export async function deriveIntentId(identity: IntentIdentityInput, key: IndexHmacKey): Promise<string> {
	assertTrustedIdentity(identity);
	return deterministicRecordId('intents', await deriveIntentIdentity(identity, key));
}

/**
 * Bind the stable business identity and the allowlisted, canonical payment details.
 * Request keys and retry controls are intentionally absent from this type and encoding. The
 * caller validates metadata against the published form's allowlist; this function independently
 * checks its runtime scalar shape, key grammar, and byte limits.
 */
export async function deriveProtectedIntentFingerprint(
	identity: IntentIdentityInput,
	details: ProtectedIntentFingerprintInput,
	key: IndexHmacKey,
): Promise<string> {
	assertTrustedIdentity(identity);
	assertFingerprintDetails(details);
	const identityHmac = await deriveIntentIdentity(identity, key);
	const detailHmac = await deriveDetailFingerprint(details, key);
	return hmacIndex(['paystack-protected-intent-v1', identityHmac, detailHmac], key);
}

/** The initial attempt is stable across transport-key changes and request replays. */
export async function deriveInitialAttemptId(intentId: string, key: IndexHmacKey): Promise<string> {
	assertIntentId(intentId);
	return `psk:v1:attempts:${await hmacIndex(['paystack-attempt-v1', intentId, '1', 'initial'], key)}`;
}

/** A successor is deterministic for one predecessor and ordinal, so concurrent retries converge. */
export async function deriveSuccessorAttemptId(
	intentId: string,
	predecessorAttemptId: string,
	ordinal: number,
	key: IndexHmacKey,
): Promise<string> {
	assertIntentId(intentId);
	assertAttemptId(predecessorAttemptId);
	if (!Number.isSafeInteger(ordinal) || ordinal < 2 || ordinal > MAX_ATTEMPTS_PER_INTENT) {
		throw new StorageInvariantError('ATTEMPT_LIMIT_EXCEEDED');
	}
	return `psk:v1:attempts:${await hmacIndex(
		['paystack-attempt-v1', intentId, String(ordinal), predecessorAttemptId],
		key,
	)}`;
}

function assertTrustedIdentity(input: IntentIdentityInput): void {
	if (!input || !input.subject || !['guest', 'member'].includes(input.subject.kind)) {
		throw new StorageInvariantError('INVALID_INTENT_IDENTITY');
	}
}

function assertFingerprintDetails(input: ProtectedIntentFingerprintInput): void {
	if (!input || !isPlainObject(input.fields) || !isPlainObject(input.metadata)) {
		throw new StorageInvariantError('INVALID_FINGERPRINT');
	}
	assertText(input.formId, 'INVALID_FORM_ID');
	assertText(input.formRevision, 'INVALID_FORM_REVISION');
	assertText(input.returnPolicy, 'INVALID_RETURN_POLICY');
	if (input.pricingMode !== 'fixed' && input.pricingMode !== 'trusted_order' && input.pricingMode !== 'payer_entered') {
		throw new StorageInvariantError('INVALID_PRICING_MODE');
	}
	if (input.method !== 'card') throw new StorageInvariantError('UNSUPPORTED_METHOD');
	if (typeof input.amountMinor !== 'string' || !/^(?:0|[1-9][0-9]*)$/u.test(input.amountMinor)) {
		throw new StorageInvariantError('INVALID_CANONICAL_AMOUNT');
	}
	const amount = BigInt(input.amountMinor);
	if (amount < MIN_NGN_MINOR || amount > MAX_NGN_MINOR) {
		throw new StorageInvariantError('INVALID_CANONICAL_AMOUNT');
	}
	const fieldEntries = Object.entries(input.fields);
	if (fieldEntries.length > MAX_FORM_FIELDS) {
		throw new StorageInvariantError('INVALID_FINGERPRINT');
	}
	for (const [id, value] of fieldEntries) {
		if (!FIELD_ID.test(id) || RESERVED_KEYS.has(id) ||
			(typeof value !== 'string' && typeof value !== 'boolean') ||
			(typeof value === 'string' && Array.from(value).length > MAX_FORM_FIELD_VALUE_LENGTH)) {
			throw new StorageInvariantError('INVALID_FINGERPRINT');
		}
	}
	for (const [metadataKey, value] of Object.entries(input.metadata)) {
		if (!METADATA_KEY.test(metadataKey) || RESERVED_KEYS.has(metadataKey) ||
			(value !== null && typeof value !== 'string' && typeof value !== 'boolean' &&
			!(typeof value === 'number' && Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value))))) {
			throw new StorageInvariantError('INVALID_FINGERPRINT');
		}
	}
	const metadataJson = canonicalJson(input.metadata);
	const encoder = new TextEncoder();
	if (encoder.encode(metadataJson).byteLength > MAX_FORM_METADATA_BYTES ||
		encoder.encode(canonicalJson({ fields: input.fields, metadata: input.metadata })).byteLength > MAX_FORM_SUBMISSION_BYTES) {
		throw new StorageInvariantError('INVALID_FINGERPRINT');
	}
}

function assertText(value: unknown, code: string): asserts value is string {
	if (typeof value !== 'string' || value.length < 1 || value.length > 1024 || /[\u0000-\u001f\u007f]/u.test(value)) {
		throw new StorageInvariantError(code);
	}
}

function assertIntentId(value: string): void {
	if (typeof value !== 'string' || !INTENT_ID.test(value)) throw new StorageInvariantError('INVALID_INTENT_ID');
}

function assertAttemptId(value: string): void {
	if (typeof value !== 'string' || !ATTEMPT_ID.test(value)) throw new StorageInvariantError('INVALID_ATTEMPT_ID');
}
