import type { AesGcmEnvelope } from '../security/encryption.js';
import { assertSupportedRecord, isPlainObject, MAX_AGGREGATE_BYTES, MAX_ATTEMPTS_PER_INTENT, StorageInvariantError, type ModelRecord, type VersionedCollection } from './schema.js';
import type { RequestKeyRecord } from './request-keys.js';

export interface AdmittedPaymentSnapshot {
	readonly schemaVersion: '1.0';
	readonly siteId: string;
	readonly subject: { readonly kind: 'guest' | 'member'; readonly id: string };
	readonly businessReference: string;
	readonly merchantProfile: string;
	readonly environment: 'test' | 'live';
	readonly credentialVersion: number;
	readonly form: unknown;
	readonly amount: { readonly currency: 'NGN'; readonly value: string; readonly minorUnits: number };
	readonly fields: Readonly<Record<string, string | boolean>>;
	readonly metadata: Readonly<Record<string, string | number | boolean | null>>;
	readonly returnDestinationId?: string;
	/** Consumer selected by the trusted server configuration at admission. */
	readonly consumerId?: string;
}

export interface InitialIntentAttempt extends ModelRecord {
	readonly id: string;
	readonly ordinal: 1;
	readonly predecessorId: null;
	readonly state: 'created';
	readonly providerState: 'not_started';
	readonly credentialVersion: number;
	readonly createTransmissionStarted: false;
	readonly providerReference: null;
	readonly providerResourceId: null;
	readonly createdAt: string;
	readonly updatedAt: string;
	readonly nextRunAt: number;
}

/** Minimal allocated intent shape consumed by the later guarded provider worker. */
export interface AdmissionIntentRecord extends ModelRecord {
	readonly modelVersion: 1;
	readonly siteId: string;
	readonly consumerId?: string;
	readonly merchantId: string;
	readonly merchantProfile: string;
	readonly environment: 'test' | 'live';
	readonly credentialVersion: number;
	readonly formId: string;
	readonly formRevision: string;
	readonly identityHmac: string;
	readonly fingerprintHmac: string;
	readonly state: 'created';
	readonly deliveryState: 'not_eligible';
	readonly currentAttemptId: string;
	readonly attempts: readonly InitialIntentAttempt[];
	readonly protectedSnapshot: AesGcmEnvelope;
	readonly leaseEpoch: 0;
	readonly nextRunAt: number;
	readonly createdAt: string;
	readonly updatedAt: string;
}

export type AdmissionCasResult = 'written' | 'conflict' | 'unknown' | 'invalid';

/** Promote a permanent key reservation only after the form eligibility CAS has linearized. */
export async function persistAdmittedSnapshot(
	collection: VersionedCollection<RequestKeyRecord>,
	reservation: RequestKeyRecord,
	revision: string,
	snapshot: AesGcmEnvelope,
	admissionSequence: number,
): Promise<AdmissionCasResult> {
	if (reservation.stage !== 'reserved' || reservation.attemptId !== null ||
		!Number.isSafeInteger(admissionSequence) || admissionSequence < 1 || !isEncryptedEnvelope(snapshot)) return 'invalid';
	return compareAndSetKey(collection, reservation, revision, {
		...reservation,
		stage: 'admitted',
		admittedSnapshot: snapshot,
		admissionSequence,
	});
}

/** Bind a key to an already allocated exact attempt; never rebind a historical key. */
export async function bindRequestKeyToAttempt(
	collection: VersionedCollection<RequestKeyRecord>,
	reservation: RequestKeyRecord,
	revision: string,
	attemptId: string,
	admittedSnapshot?: AesGcmEnvelope,
): Promise<AdmissionCasResult> {
	if (!/^psk:v1:attempts:[a-f0-9]{64}$/u.test(attemptId)) return 'invalid';
	if (reservation.stage === 'allocated') return reservation.attemptId === attemptId && reservation.accepted ? 'written' : 'invalid';
	if (reservation.stage !== 'admitted' && reservation.stage !== 'reserved') return 'invalid';
	if (reservation.stage === 'reserved' && !isEncryptedEnvelope(admittedSnapshot)) return 'invalid';
	if (admittedSnapshot !== undefined && !isEncryptedEnvelope(admittedSnapshot)) return 'invalid';
	return compareAndSetKey(collection, reservation, revision, {
		...reservation,
		stage: 'allocated',
		attemptId,
		accepted: true,
		...(admittedSnapshot ? { admittedSnapshot } : {}),
	});
}

/** Create the deterministic intent aggregate without making a provider request. */
export async function createInitialIntent(
	collection: VersionedCollection<AdmissionIntentRecord>,
	intentId: string,
	reservation: RequestKeyRecord,
	snapshot: AdmittedPaymentSnapshot,
	protectedSnapshot: AesGcmEnvelope,
	nowMs: number,
): Promise<AdmissionCasResult> {
	if (!isIntentId(intentId) || reservation.intentId !== intentId || reservation.stage !== 'admitted' ||
		!isEncryptedEnvelope(protectedSnapshot) || !Number.isSafeInteger(nowMs) || nowMs < 0 ||
		snapshot.siteId.length < 1 || (snapshot.consumerId !== undefined && !/^[A-Za-z0-9_-]{1,120}$/u.test(snapshot.consumerId)) || !Number.isSafeInteger(snapshot.credentialVersion) || snapshot.credentialVersion < 1) return 'invalid';
	const at = new Date(nowMs).toISOString();
	const attempt: InitialIntentAttempt = {
		modelVersion: 1,
		id: reservation.intendedAttemptId,
		ordinal: 1,
		predecessorId: null,
		state: 'created',
		providerState: 'not_started',
		credentialVersion: snapshot.credentialVersion,
		createTransmissionStarted: false,
		providerReference: null,
		providerResourceId: null,
		createdAt: at,
		updatedAt: at,
		nextRunAt: nowMs,
	};
	const record: AdmissionIntentRecord = {
		modelVersion: 1,
		siteId: snapshot.siteId,
		...(snapshot.consumerId ? { consumerId: snapshot.consumerId } : {}),
		merchantId: snapshot.merchantProfile,
		merchantProfile: snapshot.merchantProfile,
		environment: snapshot.environment,
		credentialVersion: snapshot.credentialVersion,
		formId: String((snapshot.form as { id?: unknown } | null)?.id ?? ''),
		formRevision: String((snapshot.form as { revision?: unknown } | null)?.revision ?? ''),
		identityHmac: intentId,
		fingerprintHmac: reservation.fingerprintHmac,
		state: 'created',
		deliveryState: 'not_eligible',
		currentAttemptId: reservation.intendedAttemptId,
		attempts: [attempt],
		protectedSnapshot,
		leaseEpoch: 0,
		nextRunAt: nowMs,
		createdAt: at,
		updatedAt: at,
	};
	if (!record.formId || !record.formRevision) return 'invalid';
	try {
		assertSupportedRecord(record);
		if (new TextEncoder().encode(JSON.stringify(record)).byteLength > MAX_AGGREGATE_BYTES) return 'invalid';
		const write = await collection.compareAndSet(intentId, null, record);
		return write.applied ? 'written' : 'conflict';
	} catch {
		// Storage may have committed after a rejected bridge response. Caller resumes by intent ID.
		return 'unknown';
	}
}

export function isAdmissionIntentRecord(value: unknown): value is AdmissionIntentRecord {
	if (!isPlainObject(value)) return false;
	try { assertSupportedRecord(value); } catch { return false; }
	if (value.modelVersion !== 1 || typeof value.siteId !== 'string' || typeof value.merchantId !== 'string' ||
		typeof value.merchantProfile !== 'string' || value.environment !== 'test' && value.environment !== 'live' ||
		!Number.isSafeInteger(value.credentialVersion) || typeof value.credentialVersion !== 'number' || value.credentialVersion < 1 ||
		typeof value.formId !== 'string' || typeof value.formRevision !== 'string' ||
		typeof value.identityHmac !== 'string' || !isIntentId(value.identityHmac) ||
		typeof value.fingerprintHmac !== 'string' || !/^[a-f0-9]{64}$/u.test(value.fingerprintHmac) ||
		value.state !== 'created' && value.state !== 'initializing' && value.state !== 'requires_action' &&
		value.state !== 'pending' && value.state !== 'unknown' && value.state !== 'verified_paid' &&
		value.state !== 'verified_failed' && value.state !== 'verified_canceled' && value.state !== 'review_required' ||
		!Array.isArray(value.attempts) || value.attempts.length < 1 || value.attempts.length > MAX_ATTEMPTS_PER_INTENT ||
		typeof value.currentAttemptId !== 'string' || !/^psk:v1:attempts:[a-f0-9]{64}$/u.test(value.currentAttemptId) ||
		!isEncryptedEnvelope(value.protectedSnapshot) || typeof value.createdAt !== 'string' || typeof value.updatedAt !== 'string') return false;
	const current = value.attempts.find((entry) => isPlainObject(entry) && entry.id === value.currentAttemptId);
	return Boolean(current);
}

function isIntentId(value: string): boolean {
	return /^psk:v1:intents:[a-f0-9]{64}$/u.test(value);
}

function isEncryptedEnvelope(value: unknown): value is AesGcmEnvelope {
	return isPlainObject(value) && value.version === 1 && value.algorithm === 'A256GCM' &&
		typeof value.keyId === 'string' && typeof value.iv === 'string' && typeof value.ciphertext === 'string';
}

async function compareAndSetKey(
	collection: VersionedCollection<RequestKeyRecord>,
	reservation: RequestKeyRecord,
	revision: string,
	updated: RequestKeyRecord,
): Promise<AdmissionCasResult> {
	if (!revision || updated.scopeKey !== reservation.scopeKey || updated.intentId !== reservation.intentId ||
		updated.fingerprintHmac !== reservation.fingerprintHmac || updated.predecessorId !== reservation.predecessorId ||
		updated.intendedAttemptId !== reservation.intendedAttemptId) return 'invalid';
	try {
		assertSupportedRecord(updated);
		if (new TextEncoder().encode(JSON.stringify(updated)).byteLength > MAX_AGGREGATE_BYTES) return 'invalid';
		const result = await collection.compareAndSet(`psk:v1:request_keys:${reservation.scopeKey}`, revision, updated);
		return result.applied ? 'written' : 'conflict';
	} catch {
		return 'unknown';
	}
}
