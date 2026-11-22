import { deriveInitialAttemptId, deriveSuccessorAttemptId } from './intent.js';
import { hmacIndex, type IndexHmacKey } from '../security/encryption.js';
import {
	assertSupportedRecord,
	isPlainObject,
	MAX_AGGREGATE_BYTES,
	MAX_ATTEMPTS_PER_INTENT,
	type ModelRecord,
	type VersionedCollection,
} from '../storage/schema.js';
import { isAdmissionIntentRecord } from '../storage/admission.js';
import { isProviderIntentRecord, type ProviderAttemptRecord, type ProviderIntentRecord } from '../storage/provider-work.js';

/** This policy is intentionally unusable until a verifier writes evidence after provider proof. */
export const PAYSTACK_RETRY_FINALITY_POLICY = 'paystack-failed-finality-v1' as const;
const FINALITY_FRESHNESS_MS = 5 * 60_000;
const MAX_FUTURE_SKEW_MS = 5_000;
const MAX_DATE_MS = 8_640_000_000_000_000;
const INTENT_ID = /^psk:v1:intents:[a-f0-9]{64}$/u;
const ATTEMPT_ID = /^psk:v1:attempts:[a-f0-9]{64}$/u;
const FINGERPRINT = /^[a-f0-9]{64}$/u;

export interface RetryFinalityEvidence {
	readonly modelVersion: 1;
	readonly policyVersion: typeof PAYSTACK_RETRY_FINALITY_POLICY;
	readonly provider: 'paystack';
	readonly profileId: string;
	readonly environment: 'test' | 'live';
	readonly credentialVersion: number;
	readonly attemptId: string;
	readonly providerReference: string;
	readonly status: 'failed';
	readonly verifiedAt: string;
	readonly profileBinding: string;
	readonly proofBinding: string;
}

export type RetryPlan =
	| { readonly kind: 'eligible'; readonly predecessor: ProviderAttemptRecord; readonly successorAttemptId: string; readonly successorOrdinal: number }
	| { readonly kind: 'reuse'; readonly predecessor: ProviderAttemptRecord; readonly successor: ProviderAttemptRecord }
	| { readonly kind: 'not_allowed' };

export type RetryCommitResult =
	| { readonly kind: 'created' | 'reused'; readonly intent: ProviderIntentRecord; readonly revision: string; readonly attempt: ProviderAttemptRecord }
	| { readonly kind: 'conflict' | 'unknown' | 'not_allowed' };

type RetryableIntent = ProviderIntentRecord & {
	readonly identityHmac: string;
	readonly fingerprintHmac: string;
};

/**
 * Evaluate a retry using only the persisted aggregate and trusted identity key. The site payload
 * cannot supply finality evidence. Existing deterministic successors are reusable; a new one
 * requires a recent, profile-bound proof which the provider verifier does not yet produce.
 */
export async function planPaymentRetry(
	value: unknown,
	predecessorAttemptId: string,
	fingerprintHmac: string,
	key: IndexHmacKey,
	nowMs: number,
): Promise<RetryPlan> {
	if (!isValidAggregate(value) || !ATTEMPT_ID.test(predecessorAttemptId) || !FINGERPRINT.test(fingerprintHmac) ||
		value.fingerprintHmac !== fingerprintHmac || !Number.isSafeInteger(nowMs) || nowMs < 0 || nowMs > MAX_DATE_MS) {
		return { kind: 'not_allowed' };
	}
	const intent = value as RetryableIntent;
	if (!await hasDeterministicAttemptChain(intent, key)) return { kind: 'not_allowed' };
	const current = intent.attempts.find((attempt) => attempt.id === intent.currentAttemptId);
	if (!current || current.state !== intent.state || intent.deliveryState !== 'not_eligible' ||
		Object.hasOwn(intent, 'receipt') || Object.hasOwn(intent, 'resultEvent')) return { kind: 'not_allowed' };
	const predecessor = intent.attempts.find((attempt) => attempt.id === predecessorAttemptId);
	if (!predecessor || predecessor.ordinal >= MAX_ATTEMPTS_PER_INTENT) return { kind: 'not_allowed' };
	const successorOrdinal = predecessor.ordinal + 1;
	const successorAttemptId = await deriveSuccessorAttemptId(
		intent.identityHmac,
		predecessorAttemptId,
		successorOrdinal,
		key,
	);
	const children = intent.attempts.filter((attempt) => (attempt as ProviderAttemptRecord & { predecessorId?: unknown }).predecessorId === predecessorAttemptId);
	if (children.length > 1) return { kind: 'not_allowed' };
	if (children.length === 1) {
		const successor = children[0]!;
		if (successor.id !== successorAttemptId || successor.ordinal !== successorOrdinal ||
			(successor as ProviderAttemptRecord & { predecessorId?: unknown }).predecessorId !== predecessorAttemptId) {
			return { kind: 'not_allowed' };
		}
		return { kind: 'reuse', predecessor, successor };
	}
	if (intent.currentAttemptId !== predecessorAttemptId || predecessor.ordinal !== intent.attempts.length ||
		intent.state !== 'verified_failed' ||
		predecessor.state !== 'verified_failed' || predecessor.providerState !== 'failed' ||
		!await hasFreshFinalityEvidence(intent, predecessor, key, nowMs)) return { kind: 'not_allowed' };
	return { kind: 'eligible', predecessor, successorAttemptId, successorOrdinal };
}

/** Perform one CAS that appends the one deterministic successor; no provider request is made. */
export async function createRetrySuccessor(
	collection: VersionedCollection<ModelRecord>,
	intentId: string,
	revision: string,
	value: unknown,
	predecessorAttemptId: string,
	fingerprintHmac: string,
	key: IndexHmacKey,
	nowMs: number,
): Promise<RetryCommitResult> {
	if (!INTENT_ID.test(intentId) || !revision || !isValidAggregate(value) ||
		(value as RetryableIntent).identityHmac !== intentId) return { kind: 'not_allowed' };
	const plan = await planPaymentRetry(value, predecessorAttemptId, fingerprintHmac, key, nowMs);
	if (plan.kind === 'not_allowed') return { kind: 'not_allowed' };
	const intent = value as RetryableIntent;
	if (plan.kind === 'reuse') return { kind: 'reused', intent, revision, attempt: plan.successor };
	const at = new Date(nowMs).toISOString();
	if (!Number.isFinite(Date.parse(at))) return { kind: 'not_allowed' };
	const nextEpoch = intent.leaseEpoch + 1;
	if (!Number.isSafeInteger(nextEpoch) || nextEpoch < 1) return { kind: 'not_allowed' };
	const successor: ProviderAttemptRecord = {
		modelVersion: 1,
		id: plan.successorAttemptId,
		ordinal: plan.successorOrdinal,
		predecessorId: predecessorAttemptId,
		state: 'created',
		providerState: 'not_started',
		credentialVersion: plan.predecessor.credentialVersion,
		createTransmissionStarted: false,
		providerReference: null,
		providerResourceId: null,
		nextRunAt: nowMs,
		createdAt: at,
		updatedAt: at,
	};
	const updated: RetryableIntent & ModelRecord = {
		...intent,
		state: 'created',
		currentAttemptId: successor.id,
		attempts: [...intent.attempts, successor],
		leaseEpoch: nextEpoch,
		lease: null,
		nextRunAt: nowMs,
		updatedAt: at,
	};
	try {
		assertSupportedRecord(updated);
		if (new TextEncoder().encode(JSON.stringify(updated)).byteLength > MAX_AGGREGATE_BYTES ||
			!isValidAggregate(updated)) return { kind: 'not_allowed' };
	} catch {
		return { kind: 'not_allowed' };
	}
	try {
		const write = await collection.compareAndSet(intentId, revision, updated);
		return write.applied && write.revision
			? { kind: 'created', intent: updated, revision: write.revision, attempt: successor }
			: write.applied ? { kind: 'unknown' } : { kind: 'conflict' };
	} catch {
		// A rejected bridge response may follow a committed CAS. Read exactly once; never retry it.
		try {
			const observed = await collection.getVersioned(intentId);
			if (!observed?.revision || !isValidAggregate(observed.value)) return { kind: 'unknown' };
			const observedIntent = observed.value as RetryableIntent;
			const observedAttempt = observedIntent.attempts.find((attempt) => attempt.id === plan.successorAttemptId);
			return observedIntent.currentAttemptId === plan.successorAttemptId &&
				observedAttempt && observedAttempt.ordinal === plan.successorOrdinal &&
				(observedAttempt as ProviderAttemptRecord & { predecessorId?: unknown }).predecessorId === predecessorAttemptId &&
				observedIntent.fingerprintHmac === fingerprintHmac
				? { kind: 'created', intent: observedIntent, revision: observed.revision, attempt: observedAttempt }
				: { kind: 'unknown' };
		} catch {
			return { kind: 'unknown' };
		}
	}
}

/** Resolve a pre-existing key's deterministic successor ordinal without trusting its payload. */
export async function matchSuccessorOrdinal(
	intentId: string,
	predecessorAttemptId: string,
	intendedAttemptId: string,
	key: IndexHmacKey,
): Promise<number | null> {
	if (!INTENT_ID.test(intentId) || !ATTEMPT_ID.test(predecessorAttemptId) || !ATTEMPT_ID.test(intendedAttemptId)) return null;
	for (let ordinal = 2; ordinal <= MAX_ATTEMPTS_PER_INTENT; ordinal += 1) {
		if (await deriveSuccessorAttemptId(intentId, predecessorAttemptId, ordinal, key) === intendedAttemptId) return ordinal;
	}
	return null;
}

async function hasFreshFinalityEvidence(
	intent: RetryableIntent,
	attempt: ProviderAttemptRecord,
	key: IndexHmacKey,
	nowMs: number,
): Promise<boolean> {
	const evidence = (attempt as ProviderAttemptRecord & { finalityEvidence?: unknown }).finalityEvidence;
	if (!isRetryFinalityEvidence(evidence) || evidence.provider !== 'paystack' ||
		evidence.policyVersion !== PAYSTACK_RETRY_FINALITY_POLICY || evidence.profileId !== intent.merchantProfile ||
		evidence.environment !== intent.environment || evidence.credentialVersion !== attempt.credentialVersion ||
		evidence.attemptId !== attempt.id || evidence.providerReference !== attempt.providerReference ||
		evidence.status !== 'failed') return false;
	const verifiedAtMs = Date.parse(evidence.verifiedAt);
	if (!Number.isSafeInteger(verifiedAtMs) || verifiedAtMs > MAX_DATE_MS || verifiedAtMs > nowMs + MAX_FUTURE_SKEW_MS ||
		nowMs - verifiedAtMs > FINALITY_FRESHNESS_MS) return false;
	const profileBinding = await hmacIndex([
		'paystack-finality-profile-v1', intent.identityHmac, intent.merchantProfile, intent.environment,
		String(attempt.credentialVersion), PAYSTACK_RETRY_FINALITY_POLICY,
	], key);
	if (evidence.profileBinding !== profileBinding) return false;
	const proofBinding = await hmacIndex([
		'paystack-finality-proof-v1', profileBinding, attempt.id, attempt.providerReference ?? '',
		evidence.verifiedAt, evidence.status,
	], key);
	return evidence.proofBinding === proofBinding;
}

function isRetryFinalityEvidence(value: unknown): value is RetryFinalityEvidence {
	if (!isPlainObject(value) || !hasExactKeys(value, [
		'modelVersion', 'policyVersion', 'provider', 'profileId', 'environment', 'credentialVersion',
		'attemptId', 'providerReference', 'status', 'verifiedAt', 'profileBinding', 'proofBinding',
	])) return false;
	return value.modelVersion === 1 && value.policyVersion === PAYSTACK_RETRY_FINALITY_POLICY &&
		value.provider === 'paystack' && typeof value.profileId === 'string' && /^[A-Za-z0-9_-]{1,120}$/u.test(value.profileId) &&
		(value.environment === 'test' || value.environment === 'live') &&
		Number.isSafeInteger(value.credentialVersion) && typeof value.credentialVersion === 'number' && value.credentialVersion >= 1 &&
		typeof value.attemptId === 'string' && ATTEMPT_ID.test(value.attemptId) &&
		typeof value.providerReference === 'string' && /^[A-Za-z0-9.=\-]{1,100}$/u.test(value.providerReference) &&
		value.status === 'failed' && typeof value.verifiedAt === 'string' && Number.isFinite(Date.parse(value.verifiedAt)) &&
		typeof value.profileBinding === 'string' && FINGERPRINT.test(value.profileBinding) &&
		typeof value.proofBinding === 'string' && FINGERPRINT.test(value.proofBinding);
}

function isValidAggregate(value: unknown): value is RetryableIntent {
	if (!isAdmissionIntentRecord(value) || !isProviderIntentRecord(value) || !isPlainObject(value) ||
		typeof value.identityHmac !== 'string' || !INTENT_ID.test(value.identityHmac) ||
		typeof value.fingerprintHmac !== 'string' || !FINGERPRINT.test(value.fingerprintHmac)) return false;
	return value.attempts.every((attempt) => isPlainObject(attempt) &&
		(typeof (attempt as Record<string, unknown>).predecessorId === 'string' ||
			(attempt as Record<string, unknown>).predecessorId === null) &&
			((attempt as Record<string, unknown>).predecessorId === null ||
				ATTEMPT_ID.test(String((attempt as Record<string, unknown>).predecessorId))));
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
	return keys.length === Object.keys(value).length && keys.every((key) => Object.hasOwn(value, key));
}

async function hasDeterministicAttemptChain(intent: RetryableIntent, key: IndexHmacKey): Promise<boolean> {
	for (let index = 0; index < intent.attempts.length; index += 1) {
		const attempt = intent.attempts[index]!;
		const predecessorId = index === 0 ? null : intent.attempts[index - 1]!.id;
		const expectedId = index === 0
			? await deriveInitialAttemptId(intent.identityHmac, key)
			: await deriveSuccessorAttemptId(intent.identityHmac, predecessorId!, index + 1, key);
		if (attempt.ordinal !== index + 1 || attempt.id !== expectedId ||
			(attempt as ProviderAttemptRecord & { predecessorId?: unknown }).predecessorId !== predecessorId) return false;
	}
	return true;
}
