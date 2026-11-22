import {
	deriveRequestKeyId,
	type IntentIdentityInput,
} from '../domain/identity.js';
import {
	deriveInitialAttemptId,
	deriveIntentId,
	deriveProtectedIntentFingerprint,
	deriveSuccessorAttemptId,
	type ProtectedIntentFingerprintInput,
} from '../domain/intent.js';
import type { IndexHmacKey } from '../security/encryption.js';
import {
	assertSupportedRecord,
	deterministicRecordId,
	MAX_AGGREGATE_BYTES,
	MAX_ATTEMPTS_PER_INTENT,
	StorageInvariantError,
	type ModelRecord,
	type VersionedCollection,
} from './schema.js';

export type RequestKeyStage = 'reserved' | 'admitted' | 'allocated';

/** Permanent minimum binding. T032 may advance stage fields but must never remove/rebind this record. */
export interface RequestKeyRecord extends ModelRecord {
	readonly modelVersion: 1;
	readonly scopeKey: string;
	readonly fingerprintHmac: string;
	readonly intentId: string;
	readonly predecessorId: string | null;
	readonly intendedAttemptId: string;
	readonly attemptId: string | null;
	readonly accepted: boolean;
	readonly stage: RequestKeyStage;
	readonly admittedSnapshot?: unknown;
	readonly admissionSequence?: number | null;
	readonly createdAt: string;
}

export interface RequestKeyReservationRequest {
	readonly identity: IntentIdentityInput;
	readonly requestKey: string;
	readonly fingerprint: ProtectedIntentFingerprintInput;
	readonly retry?: {
		readonly predecessorAttemptId: string;
		readonly successorOrdinal: number;
	};
	/** Injected only by deterministic tests; production callers omit it. */
	readonly nowMs?: number;
}

export type RequestKeyReservationResult<T extends RequestKeyRecord> =
	| { readonly kind: 'reserved'; readonly record: T; readonly revision: string }
	| { readonly kind: 'replay'; readonly record: T; readonly revision: string; readonly boundAttemptId: string }
	| { readonly kind: 'conflict'; readonly code: 'request_key_conflict' }
	| { readonly kind: 'unavailable' }
	| { readonly kind: 'unknown' };

export type RequestKeyLookup =
	| { readonly kind: 'empty'; readonly recordId: string; readonly scopeKey: string; readonly intentId: string }
	| { readonly kind: 'found'; readonly recordId: string; readonly scopeKey: string; readonly intentId: string; readonly record: RequestKeyRecord; readonly revision: string; readonly environment: IntentIdentityInput['environment'] }
	| { readonly kind: 'conflict' }
	| { readonly kind: 'unavailable' };

type ReadResult<T> =
	| { readonly kind: 'found'; readonly value: T; readonly revision: string }
	| { readonly kind: 'empty' }
	| { readonly kind: 'error' };

/**
 * Create-only reservation saga step. It never allocates the intent aggregate and never deletes or
 * retries a write whose outcome is unknown. A found record is owner-checked before replay details.
 */
export async function reserveRequestKey<T extends RequestKeyRecord>(
	collection: VersionedCollection<T>,
	request: RequestKeyReservationRequest,
	key: IndexHmacKey,
	preflight?: RequestKeyLookup,
): Promise<RequestKeyReservationResult<T>> {
	assertRequestKey(request.requestKey);
	const intentId = await deriveIntentId(request.identity, key);
	const requestKeyDigest = await deriveRequestKeyId(request.identity.siteId, request.requestKey, key);
	const recordId = deterministicRecordId('request_keys', requestKeyDigest);
	const firstRead: ReadResult<T> = preflight
		? preflightRead<T>(preflight, recordId, requestKeyDigest, intentId)
		: await readRecord(collection, recordId, requestKeyDigest);
	if (firstRead.kind === 'error') return { kind: 'unavailable' };
	if (firstRead.kind === 'found') {
		if (firstRead.value.intentId !== intentId) return keyConflict();
		const binding = await deriveBinding(request, intentId, key);
		return compareExisting(firstRead, binding);
	}

	const binding = await deriveBinding(request, intentId, key);
	const nowMs = request.nowMs ?? Date.now();
	if (!Number.isFinite(nowMs) || nowMs < 0 || !Number.isSafeInteger(nowMs)) {
		throw new StorageInvariantError('INVALID_TIMESTAMP');
	}
	const record = {
		modelVersion: 1,
		scopeKey: requestKeyDigest,
		fingerprintHmac: binding.fingerprintHmac,
		intentId,
		predecessorId: binding.predecessorId,
		intendedAttemptId: binding.intendedAttemptId,
		attemptId: null,
		accepted: false,
		stage: 'reserved',
		admittedSnapshot: null,
		admissionSequence: null,
		createdAt: new Date(nowMs).toISOString(),
	} satisfies RequestKeyRecord;
	assertSupportedRecord(record);
	if (new TextEncoder().encode(JSON.stringify(record)).byteLength > MAX_AGGREGATE_BYTES) {
		throw new StorageInvariantError('AGGREGATE_TOO_LARGE');
	}

	try {
		const created = await collection.compareAndSet(recordId, null, record as T);
		if (created.applied) return { kind: 'reserved', record: record as T, revision: created.revision };
	} catch {
		// The write can have committed despite a rejected bridge call. Read once; never reissue it.
		return resolveAfterAmbiguousWrite(collection, recordId, requestKeyDigest, intentId, binding);
	}

	const raced = await readRecord(collection, recordId, requestKeyDigest);
	if (raced.kind === 'error') return { kind: 'unknown' };
	if (raced.kind === 'empty') return { kind: 'unknown' };
	if (raced.value.intentId !== intentId) return keyConflict();
	return compareExisting(raced, binding);
}

/** Read the permanent request-key fence once so admission can select a live form or stored snapshot. */
export async function lookupRequestKey<T extends RequestKeyRecord>(
	collection: VersionedCollection<T>,
	identity: IntentIdentityInput,
	requestKey: string,
	key: IndexHmacKey,
	historicalEnvironment?: IntentIdentityInput['environment'],
): Promise<RequestKeyLookup> {
	try {
		assertRequestKey(requestKey);
		const intentId = await deriveIntentId(identity, key);
		const scopeKey = await deriveRequestKeyId(identity.siteId, requestKey, key);
		const recordId = deterministicRecordId('request_keys', scopeKey);
		const read = await readRecord(collection, recordId, scopeKey);
		if (read.kind === 'error') return { kind: 'unavailable' };
		if (read.kind === 'empty') return { kind: 'empty', recordId, scopeKey, intentId };
		let environment = identity.environment;
		if (read.value.intentId !== intentId) {
			if (!historicalEnvironment ||
				read.value.intentId !== await deriveIntentId({ ...identity, environment: historicalEnvironment }, key)) {
				return { kind: 'conflict' };
			}
			environment = historicalEnvironment;
		}
		return { kind: 'found', recordId, scopeKey, intentId: read.value.intentId, record: read.value, revision: read.revision, environment };
	} catch {
		return { kind: 'unavailable' };
	}
}

function preflightRead<T extends RequestKeyRecord>(
	preflight: RequestKeyLookup,
	recordId: string,
	scopeKey: string,
	intentId: string,
): ReadResult<T> {
	if (preflight.kind === 'conflict' || preflight.kind === 'unavailable') return { kind: 'error' };
	if (preflight.recordId !== recordId || preflight.scopeKey !== scopeKey || preflight.intentId !== intentId) {
		return { kind: 'error' };
	}
	return preflight.kind === 'empty'
		? { kind: 'empty' }
		: { kind: 'found', value: preflight.record as T, revision: preflight.revision };
}

async function deriveBinding(
	request: RequestKeyReservationRequest,
	intentId: string,
	key: IndexHmacKey,
): Promise<{ fingerprintHmac: string; predecessorId: string | null; intendedAttemptId: string }> {
	const fingerprintHmac = await deriveProtectedIntentFingerprint(request.identity, request.fingerprint, key);
	if (!request.retry) {
		return {
			fingerprintHmac,
			predecessorId: null,
			intendedAttemptId: await deriveInitialAttemptId(intentId, key),
		};
	}
	if (request.retry.successorOrdinal < 2 || request.retry.successorOrdinal > MAX_ATTEMPTS_PER_INTENT) {
		throw new StorageInvariantError('ATTEMPT_LIMIT_EXCEEDED');
	}
	return {
		fingerprintHmac,
		predecessorId: request.retry.predecessorAttemptId,
		intendedAttemptId: await deriveSuccessorAttemptId(
			intentId,
			request.retry.predecessorAttemptId,
			request.retry.successorOrdinal,
			key,
		),
	};
}

async function resolveAfterAmbiguousWrite<T extends RequestKeyRecord>(
	collection: VersionedCollection<T>,
	recordId: string,
	requestKeyDigest: string,
	intentId: string,
	binding: { fingerprintHmac: string; predecessorId: string | null; intendedAttemptId: string },
): Promise<RequestKeyReservationResult<T>> {
	const read = await readRecord(collection, recordId, requestKeyDigest);
	if (read.kind === 'error' || read.kind === 'empty') return { kind: 'unknown' };
	if (read.value.intentId !== intentId) return keyConflict();
	return compareExisting(read, binding);
}

function compareExisting<T extends RequestKeyRecord>(
	read: Extract<ReadResult<T>, { kind: 'found' }>,
	binding: { fingerprintHmac: string; predecessorId: string | null; intendedAttemptId: string },
): RequestKeyReservationResult<T> {
	const record = read.value;
	if (record.fingerprintHmac !== binding.fingerprintHmac ||
		record.predecessorId !== binding.predecessorId ||
		record.intendedAttemptId !== binding.intendedAttemptId) return keyConflict();
	return {
		kind: 'replay',
		record,
		revision: read.revision,
		boundAttemptId: record.attemptId ?? record.intendedAttemptId,
	};
}

async function readRecord<T extends RequestKeyRecord>(
	collection: VersionedCollection<T>,
	id: string,
	scopeKey: string,
): Promise<ReadResult<T>> {
	try {
		const stored = await collection.getVersioned(id);
		if (!stored) return { kind: 'empty' };
		assertSupportedRecord(stored.value);
		if (!isRequestKeyRecord(stored.value) || stored.value.scopeKey !== scopeKey) return { kind: 'error' };
		return { kind: 'found', value: stored.value, revision: stored.revision };
	} catch {
		return { kind: 'error' };
	}
}

function isRequestKeyRecord(value: unknown): value is RequestKeyRecord {
	if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
	const record = value as Record<string, unknown>;
	const validStage = record.stage === 'reserved' || record.stage === 'admitted' || record.stage === 'allocated';
	return record.modelVersion === 1 &&
		typeof record.scopeKey === 'string' && /^[a-f0-9]{64}$/u.test(record.scopeKey) &&
		typeof record.fingerprintHmac === 'string' && /^[a-f0-9]{64}$/u.test(record.fingerprintHmac) &&
		typeof record.intentId === 'string' && /^psk:v1:intents:[a-f0-9]{64}$/u.test(record.intentId) &&
		(record.predecessorId === null || (typeof record.predecessorId === 'string' && /^psk:v1:attempts:[a-f0-9]{64}$/u.test(record.predecessorId))) &&
		typeof record.intendedAttemptId === 'string' && /^psk:v1:attempts:[a-f0-9]{64}$/u.test(record.intendedAttemptId) &&
		(record.attemptId === null || (typeof record.attemptId === 'string' && /^psk:v1:attempts:[a-f0-9]{64}$/u.test(record.attemptId))) &&
		typeof record.accepted === 'boolean' && validStage &&
		(record.attemptId === null || record.attemptId === record.intendedAttemptId) &&
		(record.stage !== 'allocated' || record.attemptId === record.intendedAttemptId) &&
		typeof record.createdAt === 'string' && Number.isFinite(Date.parse(record.createdAt));
}

function keyConflict<T extends RequestKeyRecord>(): RequestKeyReservationResult<T> {
	return { kind: 'conflict', code: 'request_key_conflict' };
}

function assertRequestKey(value: unknown): asserts value is string {
	if (typeof value !== 'string' || value.length < 1 || Array.from(value).length > 255 ||
		/[\u0000-\u001f\u007f]/u.test(value)) {
		throw new StorageInvariantError('INVALID_REQUEST_KEY');
	}
}
