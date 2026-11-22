import {
	assertSupportedRecord,
	isPlainObject,
	MAX_AGGREGATE_BYTES,
	MAX_ATTEMPTS_PER_INTENT,
	type ModelRecord,
	type VersionedCollection,
} from './schema.js';
import { LEASE_DURATION_MS, type Lease } from './leases.js';

export interface ProviderCreateLease extends Lease {}

export interface ProviderCreateMarker {
	readonly attemptId: string;
	readonly workerId: string;
	readonly reference: string;
	readonly payloadDigest: string;
	readonly credentialVersion: number;
	readonly startedAt: string;
	readonly nowMs: number;
}

export interface ProviderNextAction {
	readonly id: string;
	readonly kind: 'redirect';
	readonly destination: string;
}

export interface ProviderQuotaLease extends Lease {
	readonly windowId: number;
	readonly attemptId: string;
	readonly reference: string;
}

export interface ProviderQuotaRecord extends ModelRecord {
	readonly scopeDigest: string;
	readonly windowId: number;
	readonly requestCount: number;
	readonly fenceEpoch: number;
	readonly lease: ProviderQuotaLease | null;
	readonly expiresAt: number;
}

export type ProviderQuotaReservation =
	| { readonly kind: 'reserved'; readonly record: ProviderQuotaRecord; readonly revision: string; readonly lease: ProviderQuotaLease }
	| { readonly kind: 'busy' | 'limited' | 'conflict' | 'unknown' | 'invalid' };

export type ProviderQuotaRelease = 'released' | 'stale' | 'unknown' | 'invalid';

export type ProviderCreateObservation =
	| { readonly kind: 'requires_action'; readonly nextAction: ProviderNextAction; readonly observedAt: string }
	| { readonly kind: 'unknown'; readonly nextRunAt: number; readonly observedAt: string };

export interface ProviderIntentRecord extends ModelRecord {
	readonly siteId: string;
	readonly merchantProfile: string;
	readonly environment: 'test' | 'live';
	readonly credentialVersion: number;
	readonly state: string;
	readonly currentAttemptId: string;
	readonly attempts: readonly ProviderAttemptRecord[];
	readonly leaseEpoch: number;
	readonly lease?: ProviderCreateLease | null;
	readonly updatedAt: string;
	readonly nextRunAt: number;
}

export interface ProviderAttemptRecord extends ModelRecord {
	readonly id: string;
	readonly ordinal: number;
	readonly state: string;
	readonly providerState: string;
	readonly credentialVersion: number;
	readonly createTransmissionStarted: boolean;
	readonly providerReference: string | null;
	readonly providerPayloadDigest?: string | null;
	readonly createWorkerId?: string | null;
	readonly createLeaseEpoch?: number | null;
	readonly createStartedAt?: string | null;
	readonly nextAction?: ProviderNextAction | null;
	readonly nextRunAt: number;
	readonly updatedAt: string;
}

export type MarkProviderCreateResult =
	| { readonly kind: 'marked'; readonly record: ProviderIntentRecord; readonly revision: string; readonly lease: ProviderCreateLease }
	| { readonly kind: 'already_started'; readonly record: ProviderIntentRecord; readonly revision: string; readonly attempt: ProviderAttemptRecord }
	| { readonly kind: 'busy' | 'conflict' | 'unknown' | 'invalid' };

export type PersistProviderObservationResult =
	| { readonly kind: 'written'; readonly record: ProviderIntentRecord; readonly revision: string; readonly attempt: ProviderAttemptRecord }
	| { readonly kind: 'conflict' | 'stale' | 'unknown' | 'invalid' };

const INTENT_ID = /^psk:v1:intents:[a-f0-9]{64}$/u;
const ATTEMPT_ID = /^psk:v1:attempts:[a-f0-9]{64}$/u;
const WORKER_ID = /^[a-f0-9]{32}$/u;
const PROVIDER_REFERENCE = /^[A-Za-z0-9.=\-]{1,100}$/u;
const SHA256 = /^[a-f0-9]{64}$/u;
const PROVIDER_QUOTA_ID = /^psk:v1:budgets:[a-f0-9]{64}$/u;
const PROVIDER_QUOTA_WINDOW_MS = 60_000;

/** Reserve one per-profile endpoint slot and its single-concurrency fence before provider I/O. */
export async function reserveProviderQuota(
	collection: VersionedCollection<ModelRecord>,
	quotaId: string,
	scopeDigest: string,
	owner: string,
	attemptId: string,
	reference: string,
	rateLimit: number,
	nowMs: number,
): Promise<ProviderQuotaReservation> {
	if (!PROVIDER_QUOTA_ID.test(quotaId) || quotaId !== `psk:v1:budgets:${scopeDigest}` || !SHA256.test(scopeDigest) ||
		!WORKER_ID.test(owner) || !ATTEMPT_ID.test(attemptId) || !PROVIDER_REFERENCE.test(reference) ||
		!Number.isSafeInteger(rateLimit) || rateLimit < 1 || rateLimit > 60 || !Number.isSafeInteger(nowMs) || nowMs < 0) {
		return { kind: 'invalid' };
	}
	const windowId = Math.floor(nowMs / PROVIDER_QUOTA_WINDOW_MS);
	const current = await readQuotaOnce(collection, quotaId);
	if (current?.kind === 'invalid') return { kind: 'invalid' };
	if (current.kind === 'unknown') return { kind: 'unknown' };
	const prior = current.kind === 'found' ? current.value : null;
	if (prior?.lease && prior.lease.expiresAt > nowMs) return { kind: 'busy' };
	const count = prior?.windowId === windowId ? prior.requestCount : 0;
	if (count >= rateLimit) return { kind: 'limited' };
	const epoch = Math.max(prior?.fenceEpoch ?? 0, prior?.lease?.epoch ?? 0) + 1;
	const leaseExpiresAt = nowMs + LEASE_DURATION_MS;
	const windowExpiry = (windowId + 2) * PROVIDER_QUOTA_WINDOW_MS;
	if (!Number.isSafeInteger(epoch) || epoch < 1 || !Number.isSafeInteger(leaseExpiresAt) || !Number.isSafeInteger(windowExpiry)) {
		return { kind: 'invalid' };
	}
	const lease: ProviderQuotaLease = Object.freeze({ owner, epoch, expiresAt: leaseExpiresAt, windowId, attemptId, reference });
	const record: ProviderQuotaRecord = Object.freeze({
		modelVersion: 1,
		scopeDigest,
		windowId,
		requestCount: count + 1,
		fenceEpoch: epoch,
		lease,
		expiresAt: Math.max(windowExpiry, leaseExpiresAt),
	});
	if (!isBounded(record)) return { kind: 'invalid' };
	const expectedRevision = current.kind === 'found' ? current.revision : null;
	let write: { applied: true; revision: string } | { applied: false };
	try { write = await collection.compareAndSet(quotaId, expectedRevision, record); } catch { return { kind: 'unknown' }; }
	if (!write.applied) return { kind: 'conflict' };
	if (!write.revision) return { kind: 'unknown' };
	return { kind: 'reserved', record, revision: write.revision, lease };
}

/** Release only the exact reservation revision; an expired/replaced fence is left to its owner. */
export async function releaseProviderQuota(
	collection: VersionedCollection<ModelRecord>,
	quotaId: string,
	revision: string,
	value: unknown,
	lease: ProviderQuotaLease,
): Promise<ProviderQuotaRelease> {
	if (!PROVIDER_QUOTA_ID.test(quotaId) || !revision || !isProviderQuotaRecord(value) || !isProviderQuotaLease(lease)) return 'invalid';
	if (value.lease === null || !sameQuotaLease(value.lease, lease)) return 'stale';
	const updated: ProviderQuotaRecord = Object.freeze({ ...value, lease: null });
	if (!isBounded(updated)) return 'invalid';
	try {
		const write = await collection.compareAndSet(quotaId, revision, updated);
		return write.applied && write.revision ? 'released' : write.applied ? 'unknown' : 'stale';
	} catch { return 'unknown'; }
}

/**
 * Claim the current initial attempt and persist its irreversible transmission marker in the same
 * aggregate CAS. A successful result is the sole authority to issue the provider POST.
 */
export async function markProviderCreateStarted(
	collection: VersionedCollection<ModelRecord>,
	intentId: string,
	revision: string,
	value: unknown,
	marker: ProviderCreateMarker,
): Promise<MarkProviderCreateResult> {
	if (!INTENT_ID.test(intentId) || !revision || !isProviderIntentRecord(value) ||
		value.currentAttemptId !== marker.attemptId || !ATTEMPT_ID.test(marker.attemptId) ||
		!WORKER_ID.test(marker.workerId) || !PROVIDER_REFERENCE.test(marker.reference) || !SHA256.test(marker.payloadDigest) ||
		!Number.isSafeInteger(marker.credentialVersion) || marker.credentialVersion < 1 ||
		!Number.isSafeInteger(marker.nowMs) || marker.nowMs < 0 || !isCanonicalTime(marker.startedAt, marker.nowMs)) {
		return { kind: 'invalid' };
	}
	const attempt = findAttempt(value, marker.attemptId);
	if (!attempt) return { kind: 'invalid' };
	if (attempt.createTransmissionStarted) return { kind: 'already_started', record: value, revision, attempt };
	if (value.state !== 'created' || attempt.state !== 'created' || attempt.providerState !== 'not_started' ||
		attempt.providerReference !== null || attempt.credentialVersion !== marker.credentialVersion) return { kind: 'conflict' };
	if (value.lease && value.lease.expiresAt > marker.nowMs) return { kind: 'busy' };
	const nextEpoch = Math.max(value.leaseEpoch, value.lease?.epoch ?? 0) + 1;
	const leaseExpiresAt = marker.nowMs + LEASE_DURATION_MS;
	const nextRunAt = marker.nowMs + 60_000;
	if (!Number.isSafeInteger(nextEpoch) || nextEpoch < 1 || !Number.isSafeInteger(leaseExpiresAt) || !Number.isSafeInteger(nextRunAt)) {
		return { kind: 'invalid' };
	}
	const lease: ProviderCreateLease = Object.freeze({
		owner: marker.workerId,
		epoch: nextEpoch,
		expiresAt: leaseExpiresAt,
	});
	const updatedAttempt: ProviderAttemptRecord = Object.freeze({
		...attempt,
		state: 'initializing',
		providerState: 'create_started',
		createTransmissionStarted: true,
		providerReference: marker.reference,
		providerPayloadDigest: marker.payloadDigest,
		createWorkerId: marker.workerId,
		createLeaseEpoch: nextEpoch,
		createStartedAt: marker.startedAt,
		nextRunAt,
		updatedAt: marker.startedAt,
	});
	const updated: ProviderIntentRecord = Object.freeze({
		...value,
		state: 'initializing',
		leaseEpoch: nextEpoch,
		lease,
		attempts: replaceAttempt(value.attempts, updatedAttempt),
		nextRunAt,
		updatedAt: marker.startedAt,
	});
	if (!isBounded(updated)) return { kind: 'invalid' };
	let write: { applied: true; revision: string } | { applied: false };
	try {
		write = await collection.compareAndSet(intentId, revision, updated);
	} catch {
		// Resolve an apply-then-lost-response once. No write is retried in this invocation.
		const observed = await readIntentOnce(collection, intentId);
		if (observed?.revision && sameCreateMarker(observed.value, marker, nextEpoch) && leaseOwned(observed.value, lease, marker.nowMs)) {
			return { kind: 'marked', record: observed.value, revision: observed.revision, lease };
		}
		return { kind: 'unknown' };
	}
	if (!write.applied) return { kind: 'conflict' };
	if (!write.revision) return { kind: 'unknown' };
	return { kind: 'marked', record: updated, revision: write.revision, lease };
}

/** Persist a successful hosted redirect or an uncertain provider outcome behind the same fence. */
export async function persistProviderCreateObservation(
	collection: VersionedCollection<ModelRecord>,
	intentId: string,
	revision: string,
	value: unknown,
	lease: ProviderCreateLease,
	observation: ProviderCreateObservation,
): Promise<PersistProviderObservationResult> {
	const observedAt = observation.observedAt;
	const nowMs = Date.parse(observedAt);
	if (!INTENT_ID.test(intentId) || !revision || !isProviderIntentRecord(value) ||
		!isLease(lease) || !Number.isSafeInteger(nowMs) || nowMs < 0 || !isCanonicalTime(observedAt, nowMs) ||
		!leaseOwned(value, lease, nowMs) || value.currentAttemptId.length === 0) return { kind: 'stale' };
	const attempt = findAttempt(value, value.currentAttemptId);
	if (!attempt || value.state !== 'initializing' || attempt.state !== 'initializing' || attempt.providerState !== 'create_started' ||
		!attempt.createTransmissionStarted || attempt.createWorkerId !== lease.owner ||
		attempt.createLeaseEpoch !== lease.epoch || typeof attempt.providerReference !== 'string' ||
		typeof attempt.providerPayloadDigest !== 'string') return { kind: 'conflict' };
	const successful = observation.kind === 'requires_action';
	if (successful && (!isProviderNextAction(observation.nextAction) || observation.nextAction.id !== attempt.id)) {
		return { kind: 'invalid' };
	}
	if (!successful && (!Number.isSafeInteger(observation.nextRunAt) || observation.nextRunAt < nowMs)) return { kind: 'invalid' };
	const nextRunAt = successful ? nowMs + 60_000 : observation.nextRunAt;
	if (!Number.isSafeInteger(nextRunAt)) return { kind: 'invalid' };
	const updatedAttempt: ProviderAttemptRecord = Object.freeze({
		...attempt,
		state: successful ? 'requires_action' : 'unknown',
		providerState: successful ? 'initialized' : 'unknown',
		...(successful ? { nextAction: observation.nextAction } : { nextAction: null }),
		nextRunAt,
		updatedAt: observedAt,
	});
	const updated: ProviderIntentRecord = Object.freeze({
		...value,
		state: successful ? 'requires_action' : 'unknown',
		lease: null,
		attempts: replaceAttempt(value.attempts, updatedAttempt),
		nextRunAt,
		updatedAt: observedAt,
	});
	if (!isBounded(updated)) return { kind: 'invalid' };
	let write: { applied: true; revision: string } | { applied: false };
	try {
		write = await collection.compareAndSet(intentId, revision, updated);
	} catch {
		const persisted = await readIntentOnce(collection, intentId);
		const persistedAttempt = persisted ? findAttempt(persisted.value, attempt.id) : null;
		if (persisted?.revision && persistedAttempt && persisted.value.state === updated.state &&
			persistedAttempt.providerReference === attempt.providerReference &&
			persistedAttempt.providerPayloadDigest === attempt.providerPayloadDigest &&
			persistedAttempt.createWorkerId === lease.owner && persistedAttempt.createLeaseEpoch === lease.epoch &&
			(successful
				? isProviderNextAction(persistedAttempt.nextAction) && persistedAttempt.nextAction.destination === observation.nextAction.destination
				: persistedAttempt.providerState === 'unknown')) {
			return { kind: 'written', record: persisted.value, revision: persisted.revision, attempt: persistedAttempt };
		}
		return { kind: 'unknown' };
	}
	if (!write.applied) return { kind: 'conflict' };
	if (!write.revision) return { kind: 'unknown' };
	return { kind: 'written', record: updated, revision: write.revision, attempt: updatedAttempt };
}

export function isProviderIntentRecord(value: unknown): value is ProviderIntentRecord {
	if (!isPlainObject(value) || value.modelVersion !== 1 || typeof value.siteId !== 'string' ||
		typeof value.merchantProfile !== 'string' || (value.environment !== 'test' && value.environment !== 'live') ||
		!Number.isSafeInteger(value.credentialVersion) || typeof value.credentialVersion !== 'number' || value.credentialVersion < 1 ||
		typeof value.state !== 'string' || !ATTEMPT_ID.test(String(value.currentAttemptId)) ||
		!Array.isArray(value.attempts) || value.attempts.length < 1 || value.attempts.length > MAX_ATTEMPTS_PER_INTENT ||
		!Number.isSafeInteger(value.leaseEpoch) || typeof value.leaseEpoch !== 'number' || value.leaseEpoch < 0 ||
		typeof value.updatedAt !== 'string' || !Number.isSafeInteger(value.nextRunAt) || typeof value.nextRunAt !== 'number') return false;
	if (value.lease !== undefined && value.lease !== null && !isLease(value.lease)) return false;
	const attempts = value.attempts as unknown[];
	return attempts.every(isProviderAttemptRecord) && attempts.some((attempt) => attempt.id === value.currentAttemptId);
}

export function isProviderNextAction(value: unknown): value is ProviderNextAction {
	return isPlainObject(value) && typeof value.id === 'string' && ATTEMPT_ID.test(value.id) &&
		value.kind === 'redirect' && typeof value.destination === 'string' && value.destination.length <= 2_048;
}

function isProviderAttemptRecord(value: unknown): value is ProviderAttemptRecord {
	return isPlainObject(value) && value.modelVersion === 1 && typeof value.id === 'string' && ATTEMPT_ID.test(value.id) &&
		Number.isSafeInteger(value.ordinal) && typeof value.ordinal === 'number' && value.ordinal >= 1 && value.ordinal <= MAX_ATTEMPTS_PER_INTENT &&
		typeof value.state === 'string' && typeof value.providerState === 'string' &&
		Number.isSafeInteger(value.credentialVersion) && typeof value.credentialVersion === 'number' && value.credentialVersion >= 1 &&
		typeof value.createTransmissionStarted === 'boolean' &&
		(value.providerReference === null || typeof value.providerReference === 'string' && PROVIDER_REFERENCE.test(value.providerReference)) &&
		Number.isSafeInteger(value.nextRunAt) && typeof value.nextRunAt === 'number' && typeof value.updatedAt === 'string';
}

function findAttempt(value: ProviderIntentRecord, attemptId: string): ProviderAttemptRecord | null {
	return value.attempts.find((attempt) => attempt.id === attemptId) ?? null;
}

function replaceAttempt(attempts: readonly ProviderAttemptRecord[], next: ProviderAttemptRecord): readonly ProviderAttemptRecord[] {
	return Object.freeze(attempts.map((attempt) => attempt.id === next.id ? next : attempt));
}

function isLease(value: unknown): value is ProviderCreateLease {
	return isPlainObject(value) && typeof value.owner === 'string' && WORKER_ID.test(value.owner) &&
		Number.isSafeInteger(value.epoch) && typeof value.epoch === 'number' && value.epoch > 0 &&
		Number.isSafeInteger(value.expiresAt) && typeof value.expiresAt === 'number' && value.expiresAt > 0;
}

function leaseOwned(value: ProviderIntentRecord, lease: ProviderCreateLease, nowMs: number): boolean {
	return Boolean(value.lease && value.lease.owner === lease.owner && value.lease.epoch === lease.epoch &&
		value.lease.expiresAt === lease.expiresAt && value.lease.expiresAt > nowMs);
}

function sameCreateMarker(value: unknown, marker: ProviderCreateMarker, epoch: number): value is ProviderIntentRecord {
	if (!isProviderIntentRecord(value)) return false;
	const attempt = findAttempt(value, marker.attemptId);
	return Boolean(value.state === 'initializing' && value.currentAttemptId === marker.attemptId &&
		attempt?.state === 'initializing' && attempt.providerState === 'create_started' && attempt.createTransmissionStarted &&
		attempt.providerReference === marker.reference &&
		attempt.providerPayloadDigest === marker.payloadDigest && attempt.credentialVersion === marker.credentialVersion &&
		attempt.createWorkerId === marker.workerId && attempt.createLeaseEpoch === epoch && attempt.createStartedAt === marker.startedAt);
}

async function readIntentOnce(
	collection: VersionedCollection<ModelRecord>,
	intentId: string,
): Promise<{ readonly value: ProviderIntentRecord; readonly revision: string } | null> {
	try {
		const current = await collection.getVersioned(intentId);
		if (!current || !isProviderIntentRecord(current.value) || !current.revision) return null;
		return { value: current.value, revision: current.revision };
	} catch {
		return null;
	}
}

async function readQuotaOnce(
	collection: VersionedCollection<ModelRecord>,
	quotaId: string,
): Promise<{ readonly kind: 'found'; readonly value: ProviderQuotaRecord; readonly revision: string } | { readonly kind: 'missing' | 'unknown' | 'invalid' }> {
	let current: { readonly value: ModelRecord; readonly revision: string } | null;
	try { current = await collection.getVersioned(quotaId); } catch { return { kind: 'unknown' }; }
	if (!current) return { kind: 'missing' };
	if (!current.revision || !isProviderQuotaRecord(current.value) || !isBounded(current.value) ||
		new TextEncoder().encode(JSON.stringify(current.value)).byteLength > 4_096 ||
		current.value.scopeDigest !== quotaId.slice('psk:v1:budgets:'.length)) {
		return { kind: 'invalid' };
	}
	return { kind: 'found', value: current.value, revision: current.revision };
}

function isProviderQuotaRecord(value: unknown): value is ProviderQuotaRecord {
	return isPlainObject(value) && hasExactKeys(value, ['modelVersion', 'scopeDigest', 'windowId', 'requestCount', 'fenceEpoch', 'lease', 'expiresAt']) &&
		value.modelVersion === 1 && typeof value.scopeDigest === 'string' && SHA256.test(value.scopeDigest) &&
		Number.isSafeInteger(value.windowId) && typeof value.windowId === 'number' && value.windowId >= 0 &&
		Number.isSafeInteger(value.requestCount) && typeof value.requestCount === 'number' && value.requestCount >= 1 && value.requestCount <= 60 &&
		Number.isSafeInteger(value.fenceEpoch) && typeof value.fenceEpoch === 'number' && value.fenceEpoch >= 1 &&
		(value.lease === null || isProviderQuotaLease(value.lease)) &&
		Number.isSafeInteger(value.expiresAt) && typeof value.expiresAt === 'number' && value.expiresAt > 0 &&
		(value.lease === null || value.lease.epoch === value.fenceEpoch && value.lease.windowId === value.windowId);
}

function isProviderQuotaLease(value: unknown): value is ProviderQuotaLease {
	return isPlainObject(value) && hasExactKeys(value, ['owner', 'epoch', 'expiresAt', 'windowId', 'attemptId', 'reference']) &&
		typeof value.owner === 'string' && WORKER_ID.test(value.owner) &&
		Number.isSafeInteger(value.epoch) && typeof value.epoch === 'number' && value.epoch > 0 &&
		Number.isSafeInteger(value.expiresAt) && typeof value.expiresAt === 'number' && value.expiresAt > 0 &&
		Number.isSafeInteger(value.windowId) && typeof value.windowId === 'number' && value.windowId >= 0 &&
		typeof value.attemptId === 'string' && ATTEMPT_ID.test(value.attemptId) &&
		typeof value.reference === 'string' && PROVIDER_REFERENCE.test(value.reference);
}

function sameQuotaLease(left: ProviderQuotaLease, right: ProviderQuotaLease): boolean {
	return left.owner === right.owner && left.epoch === right.epoch && left.expiresAt === right.expiresAt &&
		left.windowId === right.windowId && left.attemptId === right.attemptId && left.reference === right.reference;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
	const actual = Object.keys(value).sort();
	const wanted = [...expected].sort();
	return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}

function isCanonicalTime(value: string, nowMs: number): boolean {
	if (!Number.isSafeInteger(nowMs) || nowMs < 0) return false;
	try { return new Date(nowMs).toISOString() === value; } catch { return false; }
}

function isBounded<T extends ModelRecord>(value: T): boolean {
	try {
		assertSupportedRecord(value);
		return new TextEncoder().encode(JSON.stringify(value)).byteLength <= MAX_AGGREGATE_BYTES;
	} catch {
		return false;
	}
}
