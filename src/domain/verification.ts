import type { PluginContext } from 'emdash/plugin';
import {
	readPaymentConfiguration,
	type SettingsPort,
} from './configuration.js';
import { getExpectedPayment, readPaymentSnapshot } from './payment-snapshot.js';
import { cancelBody, readBoundedBody } from '../security/http-body.js';
import { formatNgnMinorUnits } from './money.js';
import { createVerifiedPaymentResult, isVerifiedPaymentResult, type VerifiedPaymentResult } from './result.js';
import { meterCollection, meterSettings, StageBudget, StageBudgetExceeded, waitForProvider } from '../security/limits.js';
import { readFieldEncryptionKeys, type DataEncryptionKey } from '../security/encryption.js';
import { LosslessJsonNumber, parseStrictJson } from '../security/json.js';
import { compareAndSetAggregate } from '../storage/aggregates.js';
import type { AdmittedPaymentSnapshot, AdmissionIntentRecord } from '../storage/admission.js';
import { isAdmissionIntentRecord } from '../storage/admission.js';
import { isProviderIntentRecord, isProviderNextAction, type ProviderAttemptRecord, type ProviderIntentRecord } from '../storage/provider-work.js';
import { isPlainObject, type ModelRecord, type VersionedCollection } from '../storage/schema.js';

export const PAYSTACK_VERIFY_URL = 'https://api.paystack.co/transaction/verify/';
export const MAX_PAYSTACK_VERIFY_BYTES = 256 * 1024;
export const MAX_VERIFICATION_ATTEMPTS = 8;
export const MAX_FINANCIAL_OBSERVATIONS = 8;
const INTENT_ID = /^psk:v1:intents:[a-f0-9]{64}$/u;
const ATTEMPT_ID = /^psk:v1:attempts:[a-f0-9]{64}$/u;
const REFERENCE = /^[A-Za-z0-9.=\-]{1,100}$/u;
const RESOURCE_ID = /^[1-9][0-9]{0,23}$/u;
const PAYSTACK_STATUSES = new Set(['success', 'failed', 'abandoned', 'ongoing', 'pending', 'processing', 'queued', 'reversed']);
const RETRY_DELAYS_MS = [60_000, 5 * 60_000, 15 * 60_000, 60 * 60_000, 6 * 60 * 60_000, 24 * 60 * 60_000, 24 * 60 * 60_000] as const;
const MAX_UNRESOLVED_MS = 72 * 60 * 60_000;

export interface PaystackVerifyRequest {
	readonly intentId: string;
	readonly attemptId?: string;
	/** Internal signed-event correlation guard; callers cannot replace the persisted provider reference. */
	readonly expectedReference?: string;
	/** Frozen event scope, checked against the exact persisted attempt before provider I/O. */
	readonly expectedMerchantProfile?: string;
	readonly expectedEnvironment?: 'test' | 'live';
	readonly expectedCredentialVersion?: number;
	readonly expectedAttemptOrdinal?: number;
	readonly expectedResourceId?: string;
	/** Reserved for an authenticated provider notification/admin reconciliation caller. */
	readonly forceVerification?: boolean;
}

export interface PaystackVerificationDependencies {
	readonly pluginId: string;
	readonly settings: SettingsPort;
	readonly intents: VersionedCollection<ModelRecord>;
	readonly fetch: (url: string, init?: RequestInit) => Promise<Response>;
	readonly budget?: StageBudget;
	readonly now?: () => number;
	readonly crypto?: Crypto;
}

export type PaystackVerificationResult =
	| { readonly kind: 'paid'; readonly result: VerifiedPaymentResult }
	| { readonly kind: 'pending' | 'review_required' | 'already_paid' | 'not_found' | 'conflict' | 'unavailable' | 'invalid' };

type VerificationStatus = 'success' | 'failed' | 'abandoned' | 'ongoing' | 'pending' | 'processing' | 'queued' | 'reversed';

interface ProviderVerification {
	readonly status: VerificationStatus;
	readonly resourceId: string | null;
	readonly customerId: string | null;
	readonly reference: string | null;
	readonly amountMinor: string | null;
	readonly requestedAmountMinor: string | null;
	readonly feesMinor: string | null;
	readonly currency: string | null;
	readonly domain: string | null;
	readonly customerEmail: string | null;
	readonly channel: string | null;
}

interface VerifiableAttempt extends ProviderAttemptRecord {
	readonly providerResourceId?: string | null;
	readonly verificationCount?: number;
	readonly verificationStartedAt?: string | null;
}

interface VerifiableIntent extends ProviderIntentRecord {
	readonly identityHmac: string;
	readonly formId: string;
	readonly formRevision: string;
	readonly protectedSnapshot: AdmissionIntentRecord['protectedSnapshot'];
	readonly deliveryState: string;
	readonly verifiedAt?: string;
	readonly receipt?: unknown;
	readonly resultEvent?: unknown;
	readonly resultEventId?: string;
	readonly verificationState?: string;
	readonly providerObservation?: unknown;
	readonly financialObservations?: readonly unknown[];
	readonly resultConsumerId?: string;
}

/** Verify exactly one already-created provider reference; this code never initializes a charge. */
export async function verifyPaystackTransaction(
	input: PaystackVerifyRequest,
	dependencies: PaystackVerificationDependencies,
): Promise<PaystackVerificationResult> {
	const now = dependencies.now ?? Date.now;
	let budget: StageBudget;
	try { budget = dependencies.budget ?? new StageBudget('reconciliation', now); } catch { return { kind: 'unavailable' }; }
	const settings = meterSettings(dependencies.settings, budget);
	const intents = meterCollection(dependencies.intents, budget);
	try {
		if (!isVerifyRequest(input) || !dependencies.pluginId) return { kind: 'invalid' };
		const nowMs = now();
		if (!isValidNow(nowMs)) return { kind: 'unavailable' };
		const configuration = await readPaymentConfiguration(settings);
		if (!configuration) return { kind: 'unavailable' };
		const stored = await intents.getVersioned(input.intentId);
		if (!stored) return { kind: 'not_found' };
		if (!stored.revision || !isAdmissionIntentRecord(stored.value) || !isProviderIntentRecord(stored.value)) return { kind: 'unavailable' };
		const intent = stored.value as unknown as VerifiableIntent;
		if (intent.identityHmac !== input.intentId) return { kind: 'unavailable' };
		if (intent.state === 'verified_paid' && !hasConsistentPaidState(intent)) return { kind: 'unavailable' };
		const attemptId = input.attemptId ?? intent.currentAttemptId;
		if (!ATTEMPT_ID.test(attemptId)) return { kind: 'invalid' };
		const attempt = intent.attempts.find((candidate) => candidate.id === attemptId) as VerifiableAttempt | undefined;
		if (!attempt || attempt.createTransmissionStarted !== true || typeof attempt.providerReference !== 'string' ||
			!REFERENCE.test(attempt.providerReference) || !Number.isSafeInteger(attempt.credentialVersion) || attempt.credentialVersion < 1 ||
			(attempt.providerResourceId !== undefined && attempt.providerResourceId !== null && !RESOURCE_ID.test(attempt.providerResourceId)) ||
			(attempt.verificationCount !== undefined && (!Number.isSafeInteger(attempt.verificationCount) || attempt.verificationCount < 0 || attempt.verificationCount > MAX_VERIFICATION_ATTEMPTS)) ||
			(attempt.verificationStartedAt !== undefined && attempt.verificationStartedAt !== null &&
				(!isCanonicalTimestamp(attempt.verificationStartedAt) || (attempt.verificationCount ?? 0) < 1))) {
			return { kind: 'conflict' };
		}
		if (input.expectedReference !== undefined && input.expectedReference !== attempt.providerReference ||
			input.expectedMerchantProfile !== undefined && input.expectedMerchantProfile !== intent.merchantProfile ||
			input.expectedEnvironment !== undefined && input.expectedEnvironment !== intent.environment ||
			input.expectedCredentialVersion !== undefined && input.expectedCredentialVersion !== attempt.credentialVersion ||
			input.expectedAttemptOrdinal !== undefined && input.expectedAttemptOrdinal !== attempt.ordinal) return { kind: 'conflict' };
		const isPaid = hasConsistentPaidState(intent);
		const paidEvent = isPaid ? intent.resultEvent as VerifiedPaymentResult : null;
		// A positive duplicate is only a delivery trigger; explicit reconciliation of later financial
		// observations may still force a provider read while preserving the existing paid receipt.
		if (paidEvent && input.forceVerification !== true) {
			if (attempt.id !== paidEvent.attemptId ||
				input.expectedResourceId !== undefined && input.expectedResourceId !== paidEvent.providerResourceId) {
				return { kind: 'review_required' };
			}
			return { kind: 'already_paid' };
		}
		if (intent.state === 'review_required' &&
			(input.forceVerification !== true || intent.verificationState === 'late_success')) return { kind: 'review_required' };
		const profile = configuration.profiles[intent.merchantProfile];
		const credential = profile?.credentialVersions.find((candidate) => candidate.version === attempt.credentialVersion);
		if (!profile || profile.profileId !== intent.merchantProfile || !credential || credential.environment !== intent.environment ||
			credential.version !== intent.credentialVersion) return { kind: 'unavailable' };
		const encryptionKeys = readFieldEncryptionKeys(configuration.fieldEncryptionKeyRing.keys);
		if (!encryptionKeys) return { kind: 'unavailable' };
		const snapshot = await readExpectedSnapshot(dependencies.pluginId, input.intentId, intent, encryptionKeys);
		if (!snapshot || snapshot.siteId !== intent.siteId || snapshot.merchantProfile !== intent.merchantProfile ||
			snapshot.environment !== intent.environment || snapshot.credentialVersion !== attempt.credentialVersion) return { kind: 'unavailable' };
		const expected = getExpectedPayment(snapshot);
		if (!expected) return { kind: 'unavailable' };
		const verificationStartedAt = attempt.verificationStartedAt;
		const countExhausted = (attempt.verificationCount ?? 0) >= MAX_VERIFICATION_ATTEMPTS;
		const timeExhausted = typeof verificationStartedAt === 'string' &&
			Number.isFinite(Date.parse(verificationStartedAt)) && nowMs - Date.parse(verificationStartedAt) >= MAX_UNRESOLVED_MS;
		if (!isPaid && (countExhausted || timeExhausted)) {
			if (intent.state === 'review_required') return { kind: 'review_required' };
			return await persistReview(intents, input.intentId, stored.revision, intent, attempt, 'verification_exhausted', null,
				new Date(nowMs).toISOString());
		}
		const requestUrl = `${PAYSTACK_VERIFY_URL}${encodeURIComponent(attempt.providerReference)}`;
		const wait = await budget.run('http', 'http.fetch', () => waitForProvider(
			dependencies.fetch(requestUrl, {
				method: 'GET',
				headers: { accept: 'application/json', authorization: `Bearer ${credential.secretKey}` },
				redirect: 'manual',
			}),
		));
		const provider = wait.kind === 'completed'
			? await parseVerificationResponse(wait.value, attempt.providerReference)
			: { kind: 'unavailable' as const };
		const observedMs = now();
		if (!isValidNow(observedMs)) return { kind: 'unavailable' };
		const observedAt = new Date(observedMs).toISOString();
		if (attempt.id !== intent.currentAttemptId && paidEvent?.attemptId !== attempt.id) {
			if (provider.kind === 'unavailable') return { kind: 'unavailable' };
			if (isPaid || provider.kind !== 'valid' || provider.value.status !== 'success') return { kind: 'review_required' };
			// A late success after a successor exists is ambiguous. Stop the current checkout
			// and retain both references for review without publishing a fulfillment result.
			const held = updateUnpaidObservation(intent, attempt, provider.value, observedAt, 'mismatch');
			const updated: VerifiableIntent = {
				...held,
				verificationState: 'late_success',
				nextRunAt: Number.MAX_SAFE_INTEGER,
				attempts: held.attempts.map((item) => item.id === intent.currentAttemptId
					? { ...item, state: 'review_required', nextAction: null, nextRunAt: Number.MAX_SAFE_INTEGER, updatedAt: observedAt }
					: item),
			};
			const write = await compareAndSetAggregate(intents, input.intentId, stored.revision, updated as unknown as ModelRecord);
			return write.kind === 'written' ? { kind: 'review_required' } : write.kind === 'conflict' ? { kind: 'conflict' } : { kind: 'unavailable' };
		}
		if (provider.kind === 'unavailable') {
			return await persistUnresolved(intents, input.intentId, stored.revision, intent, attempt, 'verification_unavailable', null, observedAt, observedMs);
		}
		if (provider.kind === 'unknown_status') {
			return await persistReview(intents, input.intentId, stored.revision, intent, attempt, 'unknown_provider_status', null, observedAt, true);
		}
		if (input.expectedResourceId !== undefined && provider.value.resourceId !== input.expectedResourceId) {
			return await persistReview(intents, input.intentId, stored.revision, intent, attempt, 'webhook_resource_mismatch', provider.value, observedAt);
		}
		return await persistProviderObservation({
			collection: intents,
			intentId: input.intentId,
			revision: stored.revision,
			intent,
			attempt,
			provider: provider.value,
			expected,
			observedAt,
			observedMs,
			crypto: dependencies.crypto ?? globalThis.crypto,
		});
	} catch (error) {
		if (error instanceof StageBudgetExceeded) return { kind: 'unavailable' };
		return { kind: 'unavailable' };
	}
}

/** Adapter for the EmDash sandbox. It uses the installed plugin HTTP bridge only. */
export function verifyPaystackTransactionFromContext(input: PaystackVerifyRequest, ctx: PluginContext, budget?: StageBudget): Promise<PaystackVerificationResult> {
	if (!ctx.http) return Promise.resolve({ kind: 'unavailable' });
	const settings: SettingsPort = {
		getVersioned: <T>(key: string) => ctx.settings.getVersioned<T>(key),
		compareAndSet: (key, expectedRevision, value) => ctx.settings.compareAndSet(key, expectedRevision, value),
	};
	return verifyPaystackTransaction(input, {
		pluginId: ctx.plugin.id,
		settings,
		intents: ctx.storage.intents as unknown as VersionedCollection<ModelRecord>,
		fetch: (url, init) => ctx.http!.fetch(url, init),
		...(budget ? { budget } : {}),
	});
}

export async function parseVerificationResponse(
	response: Response,
	expectedReference: string,
): Promise<{ readonly kind: 'valid'; readonly value: ProviderVerification } | { readonly kind: 'unknown_status' } | { readonly kind: 'unavailable' }> {
	if (response.status !== 200 || response.redirected || response.type === 'opaqueredirect' ||
		(response.url !== '' && !isPaystackApiUrl(response.url, expectedReference))) {
		await cancelBody(response);
		return { kind: 'unavailable' };
	}
	const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
	if (contentType !== 'application/json') { await cancelBody(response); return { kind: 'unavailable' }; }
	const body = await readBoundedBody(response, MAX_PAYSTACK_VERIFY_BYTES);
	if (!body) return { kind: 'unavailable' };
	let parsed: unknown;
	try { parsed = parseStrictJson(body, MAX_PAYSTACK_VERIFY_BYTES, { numericMode: 'lossless' }); } catch { return { kind: 'unavailable' }; }
	if (!isPlainObject(parsed) || parsed.status !== true || !isPlainObject(parsed.data)) return { kind: 'unavailable' };
	const data = parsed.data;
	if (typeof data.status !== 'string') return { kind: 'unavailable' };
	if (!PAYSTACK_STATUSES.has(data.status)) return { kind: 'unknown_status' };
	const customer = isPlainObject(data.customer) ? data.customer : null;
	return {
		kind: 'valid',
		value: Object.freeze({
			status: data.status as VerificationStatus,
			resourceId: parseResourceId(data.id),
			customerId: customer ? parseResourceId(customer.id) : null,
			reference: typeof data.reference === 'string' && REFERENCE.test(data.reference) ? data.reference : null,
			amountMinor: parseAmountMinor(data.amount),
			requestedAmountMinor: parseAmountMinor(data.requested_amount),
			feesMinor: parseAmountMinor(data.fees),
			currency: typeof data.currency === 'string' && /^[A-Z]{3}$/u.test(data.currency) ? data.currency : null,
			domain: data.domain === 'test' || data.domain === 'live' ? data.domain : null,
			customerEmail: customer && typeof customer.email === 'string' && customer.email.length <= 254 ? customer.email : null,
			channel: typeof data.channel === 'string' && /^[a-z][a-z0-9_]{0,31}$/u.test(data.channel) ? data.channel : null,
		}),
	};
}

function parseAmountMinor(value: unknown): string | null {
	const text = value instanceof LosslessJsonNumber ? value.lexeme : null;
	return text !== null && /^(?:0|[1-9][0-9]{0,17})$/u.test(text) ? text : null;
}

function parseResourceId(value: unknown): string | null {
	const text = value instanceof LosslessJsonNumber ? value.lexeme : null;
	return text !== null && RESOURCE_ID.test(text) ? text : null;
}

async function persistProviderObservation(input: {
	readonly collection: VersionedCollection<ModelRecord>;
	readonly intentId: string;
	readonly revision: string;
	readonly intent: VerifiableIntent;
	readonly attempt: VerifiableAttempt;
	readonly provider: ProviderVerification;
	readonly expected: { readonly amountMinor: number; readonly email: string };
	readonly observedAt: string;
	readonly observedMs: number;
	readonly crypto: Crypto;
}): Promise<PaystackVerificationResult> {
	const { intent, attempt, provider } = input;
	const expectationsMatch = matchesProtectedExpectations(intent, attempt, provider, input.expected);
	if (hasConsistentPaidState(intent)) {
		if (provider.status === 'reversed') {
			if (!expectationsMatch) return { kind: 'already_paid' };
			const updated = withFinancialObservation(intent, attempt, provider, input.observedAt, 'reversal');
			const write = await compareAndSetAggregate(input.collection, input.intentId, input.revision, updated as unknown as ModelRecord,
				(value) => (value as unknown as VerifiableIntent).state === 'verified_paid' &&
					(value as unknown as VerifiableIntent).resultEventId === intent.resultEventId &&
					Array.isArray((value as unknown as VerifiableIntent).financialObservations));
			return write.kind === 'written' ? { kind: 'already_paid' } : write.kind === 'conflict' ? { kind: 'conflict' } : { kind: 'unavailable' };
		}
		return { kind: 'already_paid' };
	}
	if (!expectationsMatch) {
		const updated = updateUnpaidObservation(intent, attempt, provider, input.observedAt, 'mismatch');
		const write = await compareAndSetAggregate(input.collection, input.intentId, input.revision, updated as unknown as ModelRecord);
		return write.kind === 'written' ? { kind: 'review_required' } : write.kind === 'conflict' ? { kind: 'conflict' } : { kind: 'unavailable' };
	}
	if (provider.status === 'reversed') {
		const base = withFinancialObservation(intent, attempt, provider, input.observedAt, 'reversal');
		const updated: VerifiableIntent = { ...base, state: 'review_required', verificationState: 'mismatch' };
		const write = await compareAndSetAggregate(input.collection, input.intentId, input.revision, updated as unknown as ModelRecord);
		return write.kind === 'written' ? { kind: 'review_required' } : write.kind === 'conflict' ? { kind: 'conflict' } : { kind: 'unavailable' };
	}
	if (provider.status === 'success') {
		const amountValue = formatNgnMinorUnits(input.expected.amountMinor);
		if (!amountValue || !provider.resourceId || !provider.reference) return { kind: 'unavailable' };
		const result = await createVerifiedPaymentResult({
			intentId: input.intentId,
			attemptId: attempt.id,
			formId: intent.formId,
			formRevision: intent.formRevision,
			environment: intent.environment,
			merchantProfile: intent.merchantProfile,
			amount: { currency: 'NGN', value: amountValue },
			verifiedAt: input.observedAt,
			providerResourceId: provider.resourceId,
			providerReference: provider.reference,
		}, input.crypto);
		const updated = updatePaidAggregate(intent, attempt, provider, result, input.observedAt);
		const write = await compareAndSetAggregate(input.collection, input.intentId, input.revision,
			updated as unknown as ModelRecord, (observed) => {
				const value = observed as unknown as VerifiableIntent;
				return confirmsPaidAggregate(value, result, provider);
			});
		if (write.kind === 'written') return { kind: 'paid', result };
		return write.kind === 'conflict' ? { kind: 'conflict' } : { kind: 'unavailable' };
	}
	// Paystack documents failed/abandoned and in-progress statuses, but this product has not
	// established terminal failure finality. Preserve the reference and retry read-only.
	return await persistUnresolved(input.collection, input.intentId, input.revision, intent, attempt,
		provider.status, provider, input.observedAt, input.observedMs);
}

function matchesProtectedExpectations(
	intent: VerifiableIntent, attempt: VerifiableAttempt, provider: ProviderVerification,
	expected: { readonly amountMinor: number; readonly email: string },
): boolean {
	return provider.reference === attempt.providerReference && provider.resourceId !== null &&
		(attempt.providerResourceId === undefined || attempt.providerResourceId === null || provider.resourceId === attempt.providerResourceId) &&
		matchesPaystackChargeAmount(provider, String(expected.amountMinor)) && provider.currency === 'NGN' &&
		provider.domain === intent.environment && provider.channel === 'card' && provider.customerEmail !== null &&
		sameEmail(provider.customerEmail, expected.email);
}

/** Match the merchant's protected amount while accounting for Paystack's optional fee pass-through. */
function matchesPaystackChargeAmount(provider: ProviderVerification, expectedAmountMinor: string): boolean {
	if (provider.requestedAmountMinor !== null && provider.requestedAmountMinor !== expectedAmountMinor) return false;
	if (provider.amountMinor === expectedAmountMinor) return true;
	if (provider.requestedAmountMinor !== expectedAmountMinor || provider.amountMinor === null || provider.feesMinor === null) return false;
	try {
		return BigInt(provider.amountMinor) >= BigInt(expectedAmountMinor) &&
			BigInt(provider.amountMinor) - BigInt(provider.feesMinor) === BigInt(expectedAmountMinor);
	} catch {
		return false;
	}
}

/** Validate the whole paid aggregate before exposing its private durable event. */
export function isConsistentPaidAggregate(value: unknown): boolean {
	return isAdmissionIntentRecord(value) && isProviderIntentRecord(value) &&
		hasConsistentPaidState(value as unknown as VerifiableIntent);
}

function hasConsistentPaidState(intent: VerifiableIntent): boolean {
	const event = intent.resultEvent;
	if (intent.state !== 'verified_paid' || !isVerifiedPaymentResult(event) ||
		intent.resultEventId !== event.eventId || event.intentId !== intent.identityHmac || event.paymentId !== intent.identityHmac ||
		event.merchantProfile !== intent.merchantProfile || event.environment !== intent.environment ||
		event.formId !== intent.formId || event.formRevision !== intent.formRevision ||
		(intent.deliveryState !== 'pending' && intent.deliveryState !== 'acknowledged') || !isPlainObject(intent.receipt)) return false;
	const paidAttempt = intent.attempts.find((item) => item.id === event.attemptId);
	if (!paidAttempt || paidAttempt.providerReference !== event.providerReference ||
		('providerResourceId' in paidAttempt && paidAttempt.providerResourceId !== null &&
			paidAttempt.providerResourceId !== event.providerResourceId)) return false;
	const receipt = intent.receipt;
	return receipt.provider === 'paystack' && receipt.status === 'success' &&
		receipt.providerResourceId === event.providerResourceId &&
		receipt.providerReference === event.providerReference &&
		isPlainObject(receipt.amount) && receipt.amount.currency === event.amount.currency &&
		receipt.amount.value === event.amount.value && receipt.domain === event.environment &&
		receipt.verifiedAt === event.verifiedAt;
}

function confirmsPaidAggregate(intent: VerifiableIntent, result: VerifiedPaymentResult, provider: ProviderVerification): boolean {
	if (!hasConsistentPaidState(intent) || intent.resultEventId !== result.eventId) return false;
	const receipt = intent.receipt as Record<string, unknown>;
	try {
		return JSON.stringify(intent.resultEvent) === JSON.stringify(result) &&
			receipt.providerResourceId === provider.resourceId && receipt.providerReference === provider.reference &&
			receipt.status === 'success' && receipt.domain === provider.domain &&
			isPlainObject(receipt.amount) && receipt.amount.value === result.amount.value && receipt.amount.currency === 'NGN';
	} catch { return false; }
}

async function persistUnresolved(
	collection: VersionedCollection<ModelRecord>, intentId: string, revision: string, intent: VerifiableIntent,
	attempt: VerifiableAttempt, status: string, provider: ProviderVerification | null, observedAt: string, nowMs: number,
): Promise<PaystackVerificationResult> {
	if (intent.state === 'verified_paid') return { kind: 'already_paid' };
	const count = (attempt.verificationCount ?? 0) + 1;
	const startedAt = attempt.verificationStartedAt ?? observedAt;
	const startMs = Date.parse(startedAt);
	const exhausted = count >= MAX_VERIFICATION_ATTEMPTS || !Number.isFinite(startMs) || nowMs - startMs >= MAX_UNRESOLVED_MS;
	const delay = RETRY_DELAYS_MS[Math.min(count - 1, RETRY_DELAYS_MS.length - 1)]!;
	const nextRunAt = exhausted ? Number.MAX_SAFE_INTEGER : nowMs + delay;
	const safeStatus = PAYSTACK_STATUSES.has(status) ? status : 'verification_unavailable';
	const keepAction = !exhausted && intent.state === 'requires_action' && attempt.state === 'requires_action' &&
		isProviderNextAction(attempt.nextAction) && attempt.nextAction.id === attempt.id;
	const base = updateAttempt(intent, attempt, {
		state: exhausted ? 'review_required' : keepAction ? 'requires_action' : 'unknown',
		...(keepAction ? { nextAction: attempt.nextAction } : {}),
		providerState: safeStatus,
		verificationCount: count,
		verificationStartedAt: startedAt,
		nextRunAt,
		updatedAt: observedAt,
		...(provider?.resourceId ? { providerResourceId: provider.resourceId } : {}),
	});
	const updated: VerifiableIntent = {
		...base,
		state: exhausted ? 'review_required' : keepAction ? 'requires_action' : 'unknown',
		nextRunAt,
		verificationState: 'unknown',
		providerObservation: provider ? safeProviderObservation(provider, observedAt) : { status: safeStatus, observedAt },
	};
	const write = await compareAndSetAggregate(collection, intentId, revision, updated as unknown as ModelRecord);
	if (write.kind !== 'written') return write.kind === 'conflict' ? { kind: 'conflict' } : { kind: 'unavailable' };
	return exhausted ? { kind: 'review_required' } : { kind: 'pending' };
}

async function persistReview(
	collection: VersionedCollection<ModelRecord>, intentId: string, revision: string, intent: VerifiableIntent,
	attempt: VerifiableAttempt, reason: string, provider: ProviderVerification | null, observedAt: string, recordAttempt = false,
): Promise<PaystackVerificationResult> {
	if (intent.state === 'verified_paid') return { kind: 'already_paid' };
	const base = updateAttempt(intent, attempt, {
		state: 'review_required', providerState: reason === 'unknown_provider_status' ? 'unknown_status' : 'verification_exhausted',
		...(recordAttempt ? { verificationCount: (attempt.verificationCount ?? 0) + 1,
			verificationStartedAt: attempt.verificationStartedAt ?? observedAt } : {}),
		nextRunAt: Number.MAX_SAFE_INTEGER,
		updatedAt: observedAt,
	});
	const updated: VerifiableIntent = {
		...base,
		state: 'review_required',
		verificationState: 'mismatch',
		providerObservation: provider ? safeProviderObservation(provider, observedAt) : { status: reason, observedAt },
	};
	const write = await compareAndSetAggregate(collection, intentId, revision, updated as unknown as ModelRecord);
	return write.kind === 'written' ? { kind: 'review_required' } : write.kind === 'conflict' ? { kind: 'conflict' } : { kind: 'unavailable' };
}

function updateUnpaidObservation(
	intent: VerifiableIntent, attempt: VerifiableAttempt, provider: ProviderVerification, observedAt: string,
	state: 'mismatch',
): VerifiableIntent {
	const base = updateAttempt(intent, attempt, {
		state: 'review_required', providerState: provider.status, verificationCount: (attempt.verificationCount ?? 0) + 1,
		updatedAt: observedAt, nextRunAt: Number.MAX_SAFE_INTEGER,
		...(provider.resourceId ? { providerResourceId: provider.resourceId } : {}),
	});
	return {
		...base,
		state: 'review_required',
		verificationState: state,
		providerObservation: safeProviderObservation(provider, observedAt),
	};
}

function withFinancialObservation(
	intent: VerifiableIntent, attempt: VerifiableAttempt, provider: ProviderVerification, observedAt: string,
	kind: 'reversal' | 'mismatched_success',
): VerifiableIntent {
	const observations = Array.isArray(intent.financialObservations) ? [...intent.financialObservations] : [];
	const safe = safeProviderObservation(provider, observedAt);
	if (!observations.some((item) => isPlainObject(item) && item.kind === kind && item.providerResourceId === safe.providerResourceId && item.observedAt === observedAt)) {
		if (observations.length < MAX_FINANCIAL_OBSERVATIONS) observations.push({ kind, ...safe });
	}
	return {
		...intent,
		financialObservations: observations,
		attempts: intent.attempts.map((item) => item.id === attempt.id ? { ...item, providerState: provider.status, updatedAt: observedAt } : item),
		updatedAt: observedAt,
	};
}

function updatePaidAggregate(
	intent: VerifiableIntent, attempt: VerifiableAttempt, provider: ProviderVerification,
	result: VerifiedPaymentResult, observedAt: string,
): VerifiableIntent {
	const providerObservation = safeProviderObservation(provider, observedAt);
	if (provider.customerId !== null) providerObservation.providerCustomerId = provider.customerId;
	const receipt = Object.freeze({
		provider: 'paystack',
		status: 'success',
		providerResourceId: provider.resourceId!,
		providerReference: provider.reference!,
		amount: Object.freeze({ currency: 'NGN', value: result.amount.value }),
		domain: provider.domain,
		channel: 'card',
		verifiedAt: observedAt,
	});
	return {
		...intent,
		state: 'verified_paid',
		deliveryState: 'pending',
		verifiedAt: observedAt,
		receipt,
		resultEvent: result,
		resultEventId: result.eventId,
		verificationState: 'matched',
		providerObservation,
		attempts: intent.attempts.map((item) => item.id === attempt.id ? {
			...item, state: 'succeeded', providerState: 'success', providerResourceId: provider.resourceId, nextAction: null,
			verificationCount: (attempt.verificationCount ?? 0) + 1, nextRunAt: Number.MAX_SAFE_INTEGER, updatedAt: observedAt,
		} : item),
		updatedAt: observedAt,
	};
}

function updateAttempt(intent: VerifiableIntent, attempt: VerifiableAttempt, next: Record<string, unknown>): VerifiableIntent {
	return {
		...intent,
		attempts: intent.attempts.map((item) => item.id === attempt.id ? { ...item, nextAction: null, ...next } : item),
		updatedAt: typeof next.updatedAt === 'string' ? next.updatedAt : intent.updatedAt,
	};
}

function safeProviderObservation(provider: ProviderVerification, observedAt: string): Record<string, unknown> {
	return {
		status: provider.status,
		providerResourceId: provider.resourceId,
		providerReference: provider.reference,
		amountMinor: provider.amountMinor,
		requestedAmountMinor: provider.requestedAmountMinor,
		feesMinor: provider.feesMinor,
		currency: provider.currency,
		domain: provider.domain,
		channel: provider.channel,
		observedAt,
	};
}


async function readExpectedSnapshot(
	pluginId: string, intentId: string, intent: VerifiableIntent, keys: ReadonlyMap<string, DataEncryptionKey>,
): Promise<AdmittedPaymentSnapshot | null> {
	const snapshot = await readPaymentSnapshot(pluginId, 'intents', intentId, intent.protectedSnapshot, keys);
	if (!snapshot || snapshot.siteId !== intent.siteId || snapshot.merchantProfile !== intent.merchantProfile ||
		snapshot.environment !== intent.environment || snapshot.credentialVersion !== intent.credentialVersion) return null;
	return snapshot;
}

function isVerifyRequest(value: unknown): value is PaystackVerifyRequest {
	return isPlainObject(value) && typeof value.intentId === 'string' && INTENT_ID.test(value.intentId) &&
		(value.attemptId === undefined || typeof value.attemptId === 'string' && ATTEMPT_ID.test(value.attemptId)) &&
		(value.expectedReference === undefined || typeof value.expectedReference === 'string' && REFERENCE.test(value.expectedReference)) &&
		(value.expectedMerchantProfile === undefined || typeof value.expectedMerchantProfile === 'string' && /^[A-Za-z0-9_-]{1,120}$/u.test(value.expectedMerchantProfile)) &&
		(value.expectedEnvironment === undefined || value.expectedEnvironment === 'test' || value.expectedEnvironment === 'live') &&
		(value.expectedCredentialVersion === undefined || Number.isSafeInteger(value.expectedCredentialVersion) && typeof value.expectedCredentialVersion === 'number' && value.expectedCredentialVersion >= 1) &&
		(value.expectedAttemptOrdinal === undefined || Number.isSafeInteger(value.expectedAttemptOrdinal) && typeof value.expectedAttemptOrdinal === 'number' && value.expectedAttemptOrdinal >= 1 && value.expectedAttemptOrdinal <= 10) &&
		(value.expectedResourceId === undefined || typeof value.expectedResourceId === 'string' && RESOURCE_ID.test(value.expectedResourceId)) &&
		(value.forceVerification === undefined || typeof value.forceVerification === 'boolean');
}

function sameEmail(actual: string, expected: string): boolean {
	return actual.trim().toLowerCase() === expected.trim().toLowerCase();
}

function isCanonicalTimestamp(value: string): boolean {
	const milliseconds = Date.parse(value);
	return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function isPaystackApiUrl(value: string, reference: string): boolean {
	try {
		const url = new URL(value);
		return url.toString() === `${PAYSTACK_VERIFY_URL}${encodeURIComponent(reference)}`;
	} catch { return false; }
}

function isValidNow(value: number): value is number {
	return Number.isSafeInteger(value) && value >= 0 && Number.isFinite(new Date(value).getTime());
}
