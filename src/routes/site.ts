import { readPaymentSnapshot } from '../domain/payment-snapshot.js';
import type { PluginContext, SandboxedRouteContext, SandboxedRequest } from 'emdash/plugin';
import {
	readPaymentConfiguration,
	type StoredPaymentConfiguration,
	type SettingsPort,
} from '../domain/configuration.js';
import {
	validateFieldValues,
	validateFormDefinition,
	validateFormMetadata,
	type FormDefinition,
} from '../domain/forms.js';
import { parseNgnAmount } from '../domain/money.js';
import { readPublishedFormDefinition } from '../domain/projection.js';
import {
	readFieldEncryptionKeys,
	createIndexHmacKey,
	decodeBase64Url,
	encryptValue,
	type AesGcmEnvelope,
	type DataEncryptionKey,
	type IndexHmacKey,
} from '../security/encryption.js';
import { authenticateAndParse, type NonceRecord, type SiteAttestationKey } from '../security/attestation.js';
import { hasExactKeys } from '../security/json.js';
import { readSchedulerReadiness } from '../storage/scheduler-health.js';
import { meterCollection, meterSettings, StageBudget } from '../security/limits.js';
import {
	bindRequestKeyToAttempt,
	createInitialIntent,
	isAdmissionIntentRecord,
	persistAdmittedSnapshot,
	type AdmittedPaymentSnapshot,
	type AdmissionIntentRecord,
} from '../storage/admission.js';
import {
	lookupRequestKey,
	reserveRequestKey,
	type RequestKeyRecord,
	type RequestKeyReservationRequest,
	type RequestKeyReservationResult,
} from '../storage/request-keys.js';
import {
	deterministicRecordId,
	isPlainObject,
	type ModelRecord,
	type VersionedCollection,
} from '../storage/schema.js';
import type { StoredFormRecord } from './forms.js';
import { domainError, domainOk } from './response.js';

const SUBMIT_ROUTE = 'payments/submit';
const SITE_IDENTIFIER = /^[A-Za-z0-9_-]{1,120}$/u;
const REQUEST_IDENTIFIER = /^[A-Za-z0-9_-]{1,255}$/u;
const PROTECTED_PRICE_KEYS = new Set([
	'amount', 'currency', 'pricing', 'pricingPolicy', 'resolvedOrderPrice', 'orderPrice', 'price', 'priceMinor', 'amountMinor',
	'fixedAmount', 'trustedAmount', 'donationAmount',
]);

export interface SiteSubmitDependencies {
	readonly pluginId: string;
	readonly settings: SettingsPort;
	readonly nonces: Pick<VersionedCollection<NonceRecord>, 'compareAndSet'>;
	readonly forms: VersionedCollection<StoredFormRecord>;
	readonly budgets: VersionedCollection<ModelRecord>;
	readonly requestKeys: VersionedCollection<RequestKeyRecord>;
	readonly intents: VersionedCollection<AdmissionIntentRecord>;
	readonly now?: () => number;
}

interface TrustedSubmitInput {
	readonly schemaVersion: '1.0';
	readonly siteId: string;
	readonly subject: { readonly kind: 'guest' | 'member'; readonly id: string };
	readonly businessReference: string;
	readonly merchantProfile: string;
	readonly resolvedOrderPrice?: unknown;
	readonly submission: Record<string, unknown>;
	readonly retryOfAttemptId?: string;
	readonly expectedEnvironment?: 'test' | 'live';
}

interface PreparedSubmission {
	readonly identity: {
		readonly siteId: string;
		readonly subject: TrustedSubmitInput['subject'];
		readonly merchantId: string;
		readonly environment: 'test' | 'live';
		readonly businessReference: string;
	};
	readonly reservation: RequestKeyReservationRequest;
	readonly snapshot: AdmittedPaymentSnapshot;
	readonly amount: AdmittedPaymentSnapshot['amount'];
	readonly formRecord?: { readonly value: StoredFormRecord; readonly revision: string };
}

export interface ConfigurationRuntime {
	readonly configuration: StoredPaymentConfiguration;
	readonly identityKey: IndexHmacKey;
	readonly encryptionKeys: ReadonlyMap<string, DataEncryptionKey>;
	readonly activeEncryptionKey: DataEncryptionKey;
	readonly attestationKey: SiteAttestationKey;
	/** Present only for a result-consumer key; never taken from request JSON. */
	readonly consumerId?: string;
}

/** Site-attested submit route. This route never invokes the provider. */
export async function siteSubmitRoute(routeCtx: SandboxedRouteContext, ctx: PluginContext): Promise<unknown> {
	const budget = new StageBudget('admission', () => Date.now());
	const settings = meterSettings(ctx.settings, budget);
	const wrapCollection = <T>(name: string) => meterCollection(ctx.storage[name] as VersionedCollection<T>, budget);
	const dependencies: SiteSubmitDependencies = {
		pluginId: ctx.plugin.id,
		settings,
		nonces: wrapCollection<NonceRecord>('nonces'),
		forms: wrapCollection<StoredFormRecord>('forms'),
		budgets: wrapCollection<ModelRecord>('budgets'),
		requestKeys: wrapCollection<RequestKeyRecord>('request_keys'),
		intents: wrapCollection<AdmissionIntentRecord>('intents'),
		now: () => Date.now(),
	};
	try {
		return await handleSiteSubmit(routeCtx.input, routeCtx.request, dependencies);
	} catch {
		return domainError('storage_unavailable');
	}
}

/** Domain boundary is exported for deterministic tests; production supplies the attested raw bytes. */
export async function handleSiteSubmit(
	rawBody: unknown,
	request: SandboxedRequest,
	dependencies: SiteSubmitDependencies,
): Promise<unknown> {
	const authenticated = await authenticatePaymentRoute(SUBMIT_ROUTE, rawBody, request, dependencies);
	if (!authenticated.ok) return authenticated;
	const { runtime, nowMs, body, siteId } = authenticated.value;

	const base = parseTrustedSubmitBase(body, siteId);
	if (!base.ok) return domainError(base.code);
	const profile = runtime.configuration.profiles[base.value.merchantProfile];
	const credential = profile?.credentialVersions.find((item) => item.version === profile.activeCredentialVersion);
	if (!profile || !credential) return domainError('provider_unavailable');
	const activeIdentity = {
		siteId: base.value.siteId,
		subject: base.value.subject,
		merchantId: profile.profileId,
		environment: credential.environment,
		businessReference: base.value.businessReference,
	} as const;

	const historicalEnvironment = credential.environment === 'test' ? 'live' : 'test';
	const lookup = await lookupRequestKey(
		dependencies.requestKeys, activeIdentity, base.value.submission.requestKey as string, runtime.identityKey,
		profile.credentialVersions.some((version) => version.environment === historicalEnvironment) ? historicalEnvironment : undefined,
	);
	if (lookup.kind === 'conflict') return domainError('request_key_conflict');
	if (lookup.kind === 'unavailable') return domainError('storage_unavailable');

	const identity = lookup.kind === 'found' ? { ...activeIdentity, environment: lookup.environment } : activeIdentity;
	if (base.value.expectedEnvironment !== undefined && identity.environment !== base.value.expectedEnvironment) {
		return domainError('forbidden');
	}
	const intentId = lookup.intentId;
	if (base.value.retryOfAttemptId) {
		return domainError('retry_not_allowed');
	}
	let prepared: PreparedSubmission;
	let reservationResult: RequestKeyReservationResult<RequestKeyRecord>;
	let intentPrefetched: Awaited<ReturnType<typeof readIntent>> | null = null;
	let admittedSnapshot: AdmittedPaymentSnapshot | null = null;

	if (lookup.kind === 'found' && lookup.record.stage !== 'reserved') {
		admittedSnapshot = await decryptAdmittedSnapshot(runtime, dependencies.pluginId, lookup.record, lookup.recordId);
		if (!admittedSnapshot) return domainError('storage_unavailable');
		const result = prepareAgainstForm(base.value, admittedSnapshot.form, identity, admittedSnapshot.credentialVersion, runtime.identityKey);
		if (!result.ok) return domainError(result.code);
		prepared = { ...result.value, snapshot: admittedSnapshot, amount: result.value.amount };
		reservationResult = await reserveRequestKey(dependencies.requestKeys, prepared.reservation, runtime.identityKey, lookup);
		intentPrefetched = await readIntent(dependencies.intents, intentId);
	} else {
		intentPrefetched = await readIntent(dependencies.intents, intentId);
		if (intentPrefetched.kind === 'error') return domainError('storage_unavailable');
		if (intentPrefetched.kind === 'found') {
			admittedSnapshot = await decryptIntentSnapshot(runtime, dependencies.pluginId, intentPrefetched.value, intentId);
			if (!admittedSnapshot) return domainError('storage_unavailable');
			const result = prepareAgainstForm(base.value, admittedSnapshot.form, identity, admittedSnapshot.credentialVersion, runtime.identityKey);
			if (!result.ok) return domainError(result.code);
			prepared = result.value;
		} else {
			if (!(await readSchedulerReadiness(dependencies.budgets, nowMs)).ready) return domainError('review_required');
			// A bare reservation carries no durable credential snapshot. Do not advance it after a mode change.
			if (identity.environment !== credential.environment) return domainError('review_required');
			const storedForm = await readPublishedForm(dependencies.forms, base.value.submission);
			if (!storedForm.ok) return domainError(storedForm.code);
			const result = prepareAgainstForm(base.value, storedForm.form, identity, credential.version, runtime.identityKey, storedForm.formRecord);
			if (!result.ok) return domainError(result.code);
			const consumers = new Set(runtime.configuration.integrationKeys
				.filter((key) => key.siteId === identity.siteId && key.purpose === 'result-consumer')
				.map((key) => key.consumerId).filter((value): value is string => typeof value === 'string'));
			if (consumers.size > 1) return domainError('review_required');
			const consumerId = consumers.values().next().value as string | undefined;
			prepared = { ...result.value, snapshot: { ...result.value.snapshot, ...(consumerId ? { consumerId } : {}) } };
		}
		reservationResult = await reserveRequestKey(dependencies.requestKeys, prepared.reservation, runtime.identityKey, lookup);
	}
	if (reservationResult.kind === 'conflict') return domainError('request_key_conflict');
	if (reservationResult.kind === 'unavailable') return domainError('storage_unavailable');
	if (reservationResult.kind === 'unknown') return domainError('storage_unavailable');

	const reservation = reservationResult.record;
	const reservationRevision = reservationResult.revision;
	if (!intentPrefetched) intentPrefetched = await readIntent(dependencies.intents, reservation.intentId);
	if (intentPrefetched.kind === 'error') return domainError('storage_unavailable');
	if (intentPrefetched.kind === 'found') {
		if (intentPrefetched.value.fingerprintHmac !== reservation.fingerprintHmac || intentPrefetched.value.identityHmac !== reservation.intentId) {
			return domainError('intent_conflict');
		}
		const boundAttemptId = reservation.stage === 'allocated' ? reservation.attemptId : intentPrefetched.value.currentAttemptId;
		if (!boundAttemptId) return domainError('storage_unavailable');
		const attempt = intentPrefetched.value.attempts.find((item) => isPlainObject(item) && item.id === boundAttemptId);
		if (!attempt) return domainError('storage_unavailable');
		if (reservation.stage !== 'allocated') {
			let replaySnapshot: AesGcmEnvelope | undefined;
			if (reservation.stage === 'reserved') {
				const snapshot = admittedSnapshot ?? await decryptIntentSnapshot(
					runtime, dependencies.pluginId, intentPrefetched.value, reservation.intentId,
				);
				if (!snapshot) return domainError('storage_unavailable');
				replaySnapshot = await encryptSnapshot(
					dependencies.pluginId,
					'request_keys',
					deterministicRecordId('request_keys', reservation.scopeKey),
					snapshot,
					runtime.activeEncryptionKey,
				) ?? undefined;
				if (!replaySnapshot) return domainError('storage_unavailable');
			}
			const bind = await bindRequestKeyToAttempt(
				dependencies.requestKeys,
				reservation,
				reservationRevision,
				intentPrefetched.value.currentAttemptId,
				replaySnapshot,
			);
			if (bind !== 'written') return pendingStatus(reservation.intentId, 'allocation');
		}
		return domainOk(statusForIntent(intentPrefetched.value, attempt, prepared.amount, 'existing_intent'));
	}

	if (reservation.stage === 'allocated') return domainError('storage_unavailable');
	// Splitting the initial reservation keeps the health read within the stage call budget.
	if (lookup.kind === 'empty' && reservation.stage === 'reserved') return pendingStatus(reservation.intentId, 'admission');
	if (reservation.stage === 'reserved') {
		if (runtime.configuration.paused) return domainError('review_required');
		const formRecord = prepared.formRecord;
		if (!formRecord) return domainError('storage_unavailable');
		const nextSequence = formRecord.value.admissionSequence + 1;
		if (!Number.isSafeInteger(nextSequence) || nextSequence < 1) return domainError('review_required');
		const keyRecordId = lookup.kind === 'found' ? lookup.recordId : deterministicRecordId('request_keys', reservation.scopeKey);
		const snapshotForKey = await encryptSnapshot(
			dependencies.pluginId, 'request_keys', keyRecordId, prepared.snapshot, runtime.activeEncryptionKey,
		);
		if (!snapshotForKey) return domainError('storage_unavailable');
		let formWrite: { readonly applied: boolean };
		try {
			formWrite = await dependencies.forms.compareAndSet(
				formRecord.value.definition.id,
				formRecord.revision,
				{ ...formRecord.value, admissionSequence: nextSequence },
			);
		} catch {
			return pendingStatus(reservation.intentId, 'admission');
		}
		if (!formWrite.applied) return pendingStatus(reservation.intentId, 'admission');
		const keyWrite = await persistAdmittedSnapshot(dependencies.requestKeys, reservation, reservationRevision, snapshotForKey, nextSequence);
		return pendingStatus(reservation.intentId, keyWrite === 'written' ? 'allocation' : 'admission');
	}

	if (reservation.stage !== 'admitted') return domainError('storage_unavailable');
	if (!admittedSnapshot) admittedSnapshot = await decryptAdmittedSnapshot(
		runtime, dependencies.pluginId, reservation, lookup.kind === 'found' ? lookup.recordId : deterministicRecordId('request_keys', reservation.scopeKey),
	);
	if (!admittedSnapshot || !isAdmittedSnapshot(admittedSnapshot)) return domainError('storage_unavailable');
	const protectedSnapshot = await encryptSnapshot(
		dependencies.pluginId, 'intents', reservation.intentId, admittedSnapshot, runtime.activeEncryptionKey,
	);
	if (!protectedSnapshot) return domainError('storage_unavailable');
	const create = await createInitialIntent(dependencies.intents, reservation.intentId, reservation, admittedSnapshot, protectedSnapshot, nowMs);
	if (create === 'invalid' || create === 'unknown') return pendingStatus(reservation.intentId, 'allocation');
	const allocated = await readIntent(dependencies.intents, reservation.intentId);
	if (allocated.kind !== 'found' || !isAdmissionIntentRecord(allocated.value)) return pendingStatus(reservation.intentId, 'allocation');
	if (allocated.value.fingerprintHmac !== reservation.fingerprintHmac) return domainError('intent_conflict');
	const bind = await bindRequestKeyToAttempt(dependencies.requestKeys, reservation, reservationRevision, allocated.value.currentAttemptId);
	if (bind !== 'written') return pendingStatus(reservation.intentId, 'allocation');
	const attempt = allocated.value.attempts.find((item) => item.id === allocated.value.currentAttemptId);
	if (!attempt) return domainError('storage_unavailable');
	return domainOk(statusForIntent(allocated.value, attempt, admittedSnapshot.amount, create === 'written' ? 'new_attempt' : 'existing_intent'));
}

type PaymentRouteDependencies = Pick<SiteSubmitDependencies, 'pluginId' | 'settings' | 'nonces' | 'now'>;

/** All site routes authenticate the original bytes against their own route and key purpose. */
export async function authenticatePaymentRoute(
	route: 'payments/submit' | 'payments/action' | 'payments/status' | 'results/feed' | 'results/ack',
	rawBody: unknown,
	request: SandboxedRequest,
	dependencies: PaymentRouteDependencies,
) {
	if (!(rawBody instanceof Uint8Array) || rawBody.byteLength > 65_536 || request.method !== 'POST') {
		return domainError('validation_error');
	}
	const nowMs = dependencies.now?.() ?? Date.now();
	if (!Number.isSafeInteger(nowMs) || nowMs < 0) return domainError('storage_unavailable');
	const resultRoute = route === 'results/feed' || route === 'results/ack';
	const runtime = await loadConfigurationRuntime(dependencies, request, resultRoute ? 'result-consumer' : 'site-payment');
	if (!runtime || (resultRoute && !runtime.consumerId)) {
		return domainError(resultRoute ? 'unauthorized' : 'provider_unavailable');
	}
	const authenticated = await authenticateAndParse({
		provider: 'paystack', method: request.method, route, rawBody,
		headers: request.headers, nowMs, keys: [runtime.attestationKey],
	}, runtime.identityKey, dependencies.nonces);
	if (!authenticated.ok) return domainError(authenticated.code === 'temporarily_unavailable' ? 'storage_unavailable' :
		authenticated.code === 'invalid_request' ? 'validation_error' : 'unauthorized');
	return domainOk({ runtime, nowMs, body: authenticated.body, siteId: authenticated.attestation.siteId });
}

export async function loadConfigurationRuntime(
	dependencies: Pick<SiteSubmitDependencies, 'pluginId' | 'settings'>,
	request: SandboxedRequest,
	purpose: 'site-payment' | 'result-consumer' = 'site-payment',
): Promise<ConfigurationRuntime | null> {
	const siteId = request.headers['x-payment-site-id'];
	const keyId = request.headers['x-payment-key-id'];
	if (!SITE_IDENTIFIER.test(siteId ?? '') || !SITE_IDENTIFIER.test(keyId ?? '')) return null;
	const configuration = await readPaymentConfiguration(dependencies.settings);
	if (!configuration) return null;
	const integration = configuration.integrationKeys.filter((entry) =>
		entry.siteId === siteId && entry.keyId === keyId && entry.purpose === purpose);
	if (integration.length !== 1) return null;
	let attestationMaterial: Uint8Array;
	try { attestationMaterial = decodeBase64Url(integration[0]!.secretBase64url); } catch { return null; }
	const identityKeyVersion = configuration.identityHmacKeyRing.keys.find((entry) => entry.keyId === configuration.identityHmacKeyRing.activeKeyId);
	if (!identityKeyVersion) return null;
	let identityKey: IndexHmacKey;
	try { identityKey = createIndexHmacKey(identityKeyVersion.keyId, decodeBase64Url(identityKeyVersion.material)); } catch { return null; }
	const encryptionKeys = readFieldEncryptionKeys(configuration.fieldEncryptionKeyRing.keys);
	if (!encryptionKeys) return null;
	const activeEncryptionKey = encryptionKeys.get(configuration.fieldEncryptionKeyRing.activeKeyId);
	if (!activeEncryptionKey) return null;
	const attestationKey: SiteAttestationKey = {
			provider: 'paystack', siteId: siteId!, keyId: keyId!, purpose, material: attestationMaterial, state: 'current',
	};
	return { configuration, identityKey, encryptionKeys, activeEncryptionKey, attestationKey,
		...(purpose === 'result-consumer' && integration[0]!.consumerId ? { consumerId: integration[0]!.consumerId } : {}) };
}

function parseTrustedSubmitBase(input: unknown, attestedSiteId: string): { readonly ok: true; readonly value: TrustedSubmitInput } | { readonly ok: false; readonly code: 'validation_error' | 'unsupported_schema' } {
	if (!isPlainObject(input) || !hasExactKeys(input,
		['schemaVersion', 'siteId', 'subject', 'businessReference', 'merchantProfile', 'submission'],
		['resolvedOrderPrice', 'retryOfAttemptId', 'expectedEnvironment'])) return { ok: false, code: 'validation_error' };
	if (input.schemaVersion !== '1.0') return { ok: false, code: 'unsupported_schema' };
	if (input.siteId !== attestedSiteId || !isSafeIdentifier(input.siteId) || !isPlainObject(input.subject) ||
		!hasExactKeys(input.subject, ['kind', 'id']) ||
		(input.subject.kind !== 'guest' && input.subject.kind !== 'member') || !isSafeIdentifier(input.subject.id) ||
		!isSafeIdentifier(input.businessReference) || !isSafeIdentifier(input.merchantProfile) || !isPlainObject(input.submission)) {
		return { ok: false, code: 'validation_error' };
	}
	const submission = input.submission;
	if (!isSafeIdentifier(submission.formId) || !isSafeIdentifier(submission.formRevision) ||
		!isSafeIdentifier(submission.requestKey)) return { ok: false, code: 'validation_error' };
	if (input.expectedEnvironment !== undefined && input.expectedEnvironment !== 'test' && input.expectedEnvironment !== 'live') {
		return { ok: false, code: 'validation_error' };
	}
	if (Object.hasOwn(input, 'retryOfAttemptId') && !isSafeIdentifier(input.retryOfAttemptId)) return { ok: false, code: 'validation_error' };
	return {
		ok: true,
		value: {
			schemaVersion: '1.0', siteId: input.siteId, subject: input.subject as TrustedSubmitInput['subject'],
			businessReference: input.businessReference, merchantProfile: input.merchantProfile,
			submission,
			...(input.expectedEnvironment !== undefined ? { expectedEnvironment: input.expectedEnvironment } : {}),
			...(Object.hasOwn(input, 'resolvedOrderPrice') ? { resolvedOrderPrice: input.resolvedOrderPrice } : {}),
			...(typeof input.retryOfAttemptId === 'string' ? { retryOfAttemptId: input.retryOfAttemptId } : {}),
		},
	};
}

async function readPublishedForm(
	forms: VersionedCollection<StoredFormRecord>,
	submission: Record<string, unknown>,
): Promise<{ readonly ok: true; readonly form: FormDefinition; readonly formRecord: { readonly value: StoredFormRecord; readonly revision: string } } | { readonly ok: false; readonly code: 'form_unavailable' | 'storage_unavailable' | 'unsupported_schema' }> {
	try {
		const stored = await forms.getVersioned(String(submission.formId));
		if (!stored) return { ok: false, code: 'form_unavailable' };
		const current = readPublishedFormDefinition(stored.value, String(submission.formId), submission.schemaVersion);
		if (!current.ok) return { ok: false, code: current.error.code === 'storage_unavailable' ? 'storage_unavailable' :
			current.error.code === 'unsupported_schema' ? 'unsupported_schema' : 'form_unavailable' };
		if (current.value.revision !== submission.formRevision) return { ok: false, code: 'form_unavailable' };
		return { ok: true, form: current.value, formRecord: { value: stored.value, revision: stored.revision } };
	} catch {
		return { ok: false, code: 'storage_unavailable' };
	}
}

function prepareAgainstForm(
	base: TrustedSubmitInput,
	formInput: unknown,
	identity: PreparedSubmission['identity'],
	credentialVersion: number,
	key: IndexHmacKey,
formRecord?: { readonly value: StoredFormRecord; readonly revision: string },
): { readonly ok: true; readonly value: PreparedSubmission } | { readonly ok: false; readonly code: 'validation_error' | 'form_unavailable' | 'protected_field_override' | 'unsupported_schema' } {
	const validatedForm = validateFormDefinition(formInput);
	if (!validatedForm.ok || validatedForm.value.id !== base.submission.formId ||
		validatedForm.value.revision !== base.submission.formRevision || validatedForm.value.state !== 'published') {
		return { ok: false, code: 'form_unavailable' };
	}
	const form = validatedForm.value;
	const submission = base.submission;
	if (submission.schemaVersion !== '1.0') return { ok: false, code: 'unsupported_schema' };
	if (!hasExactKeys(submission, ['schemaVersion', 'formId', 'formRevision', 'requestKey', 'fields'], ['payerAmount', 'metadata'])) {
		if (Object.keys(submission).some((name) => PROTECTED_PRICE_KEYS.has(name))) return { ok: false, code: 'protected_field_override' };
		return { ok: false, code: 'validation_error' };
	}
	if (form.pricing.mode === 'fixed' && (Object.hasOwn(submission, 'payerAmount') || Object.hasOwn(base, 'resolvedOrderPrice')) ||
		form.pricing.mode === 'trusted_order' && (Object.hasOwn(submission, 'payerAmount') || !Object.hasOwn(base, 'resolvedOrderPrice')) ||
		form.pricing.mode === 'payer_entered' && Object.hasOwn(base, 'resolvedOrderPrice')) {
		return { ok: false, code: 'protected_field_override' };
	}
	const fieldValues = validateFieldValues(form, submission.fields);
	if (!fieldValues.ok) return { ok: false, code: 'validation_error' };
	const metadata = validateFormMetadata(form.metadataPolicy, submission.metadata ?? Object.create(null));
	if (!metadata.ok) return { ok: false, code: 'validation_error' };
	let money: ReturnType<typeof parseNgnAmount>;
	if (form.pricing.mode === 'fixed') money = parseNgnAmount(form.pricing.amount);
	else if (form.pricing.mode === 'trusted_order') {
		if (!isNgnMoney(base.resolvedOrderPrice)) return { ok: false, code: 'protected_field_override' };
		money = parseNgnAmount(base.resolvedOrderPrice.value);
	} else {
		const minimum = parseNgnAmount(form.pricing.minimum);
		const maximum = parseNgnAmount(form.pricing.maximum);
		if (!minimum.ok || !maximum.ok || typeof submission.payerAmount !== 'string') return { ok: false, code: 'validation_error' };
		money = parseNgnAmount(submission.payerAmount, { minimumMinorUnits: minimum.money.minorUnits, maximumMinorUnits: maximum.money.minorUnits });
	}
	if (!money.ok) return { ok: false, code: 'validation_error' };
	const details = {
		formId: form.id,
		formRevision: form.revision,
		pricingMode: form.pricing.mode,
		amountMinor: String(money.money.minorUnits),
		fields: fieldValues.value,
		metadata: metadata.value,
		method: 'card' as const,
		returnPolicy: form.returnDestinationId ?? 'site-default',
	};
	const snapshot: AdmittedPaymentSnapshot = {
		schemaVersion: '1.0',
		siteId: identity.siteId,
		subject: identity.subject,
		businessReference: identity.businessReference,
		merchantProfile: identity.merchantId,
		environment: identity.environment,
		credentialVersion,
		form,
		amount: { currency: 'NGN', value: money.money.value, minorUnits: money.money.minorUnits },
		fields: fieldValues.value,
		metadata: metadata.value,
		...(form.returnDestinationId ? { returnDestinationId: form.returnDestinationId } : {}),
	};
	return {
		ok: true,
		value: {
			identity,
			reservation: { identity, requestKey: String(submission.requestKey), fingerprint: details },
			snapshot,
			amount: snapshot.amount,
			...(formRecord ? { formRecord } : {}),
		},
	};
}

async function readIntent(
	intents: VersionedCollection<AdmissionIntentRecord>,
	intentId: string,
): Promise<{ readonly kind: 'found'; readonly value: AdmissionIntentRecord; readonly revision: string } | { readonly kind: 'empty' | 'error' }> {
	try {
		const stored = await intents.getVersioned(intentId);
		if (!stored) return { kind: 'empty' };
		if (!isAdmissionIntentRecord(stored.value)) return { kind: 'error' };
		return { kind: 'found', value: stored.value, revision: stored.revision };
	} catch {
		return { kind: 'error' };
	}
}

async function decryptAdmittedSnapshot(
	runtime: ConfigurationRuntime,
	pluginId: string,
	reservation: RequestKeyRecord,
	recordId: string,
): Promise<AdmittedPaymentSnapshot | null> {
	const snapshot = await readPaymentSnapshot(pluginId, 'request_keys', recordId, reservation.admittedSnapshot, runtime.encryptionKeys);
	return isAdmittedSnapshot(snapshot) ? snapshot : null;
}

export async function decryptIntentSnapshot(
	runtime: ConfigurationRuntime,
	pluginId: string,
	intent: AdmissionIntentRecord,
	intentId: string,
): Promise<AdmittedPaymentSnapshot | null> {
	const snapshot = await readPaymentSnapshot(pluginId, 'intents', intentId, intent.protectedSnapshot, runtime.encryptionKeys);
	return isAdmittedSnapshot(snapshot) ? snapshot : null;
}

async function encryptSnapshot(
	pluginId: string,
	collection: 'request_keys' | 'intents',
	recordId: string,
	snapshot: AdmittedPaymentSnapshot,
	key: DataEncryptionKey,
): Promise<AesGcmEnvelope | null> {
	try {
		return await encryptValue(snapshot, key, { pluginId, collection, recordId, schemaVersion: 1, purpose: 'custom_fields' });
	} catch { return null; }
}

function isAdmittedSnapshot(value: AdmittedPaymentSnapshot | null): value is AdmittedPaymentSnapshot {
	return !!value && isSafeIdentifier(value.siteId) && isSafeIdentifier(value.subject.id) &&
		isSafeIdentifier(value.businessReference) && isSafeIdentifier(value.merchantProfile) &&
		(value.consumerId === undefined || isSafeIdentifier(value.consumerId)) &&
		Number.isSafeInteger(value.amount.minorUnits) && validateFormDefinition(value.form).ok;
}

function statusForIntent(
	intent: AdmissionIntentRecord,
	attempt: ModelRecord,
	amount: AdmittedPaymentSnapshot['amount'],
	outcome: 'new_attempt' | 'existing_intent',
) {
	const state = isAttemptState(attempt.state) ? attempt.state : 'unknown';
	return {
		schemaVersion: '1.0',
		intentId: intent.identityHmac,
		attemptId: String(attempt.id),
		state,
		outcome,
		amount: { currency: 'NGN', value: amount.value },
		deliveryState: intent.deliveryState,
		stage: 'provider_work',
	};
}

function pendingStatus(intentId: string, stage: 'admission' | 'allocation') {
	return domainOk({
		schemaVersion: '1.0',
		intentId,
		state: 'initializing',
		deliveryState: 'not_eligible',
		stage,
	});
}

function isAttemptState(value: unknown): value is 'created' | 'initializing' | 'requires_action' | 'pending' | 'unknown' | 'verified_paid' | 'verified_failed' | 'verified_canceled' | 'review_required' {
	return ['created', 'initializing', 'requires_action', 'pending', 'unknown', 'verified_paid', 'verified_failed', 'verified_canceled', 'review_required'].includes(String(value));
}

function isNgnMoney(value: unknown): value is { readonly currency: 'NGN'; readonly value: string } {
	return isPlainObject(value) && hasExactKeys(value, ['currency', 'value']) && value.currency === 'NGN' && typeof value.value === 'string';
}

function isSafeIdentifier(value: unknown): value is string {
	return typeof value === 'string' && value.length > 0 && Array.from(value).length <= 255 &&
		!/[\u0000-\u001f\u007f]/u.test(value);
}
