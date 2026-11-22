import { isVerifiedPaymentResult, type VerifiedPaymentResult } from '../domain/result.js';
import { validateFieldValues, validateFormDefinition } from '../domain/forms.js';
import {
	decryptValue,
	encryptValue,
	hmacIndex,
	type AesGcmEnvelope,
	type DataEncryptionKey,
	type IndexHmacKey,
} from '../security/encryption.js';
import { isPlainObject, type ModelRecord, type VersionedCollection, deterministicRecordId, assertSupportedRecord } from './schema.js';
import { isAdmissionIntentRecord, type AdmittedPaymentSnapshot } from './admission.js';
import { isProviderIntentRecord } from './provider-work.js';

const PROVIDER_CUSTOMER_ID = /^[1-9][0-9]{0,23}$/u;
const INTENT_ID = /^psk:v1:intents:[a-f0-9]{64}$/u;
const CUSTOMER_CORRELATION_ID = /^psk:v1:customers:[a-f0-9]{64}$/u;

export interface CustomerMappingRecord extends ModelRecord {
	readonly modelVersion: 1;
	readonly customerCorrelationId: string;
	readonly subjectCorrelationId: string;
	readonly providerCustomerId: string;
	readonly profileId: string;
	readonly environment: 'test' | 'live';
	readonly mappingState: 'mapped';
	readonly encryptedEmail: AesGcmEnvelope;
	readonly emailVerifiedAt: string;
	readonly createdAt: string;
	readonly updatedAt: string;
}

export interface RepairCustomerMappingInput {
	readonly pluginId: string;
	readonly intentId: string;
	readonly intent: unknown;
	readonly nowMs: number;
}

export interface CustomerMappingDependencies {
	readonly customers: VersionedCollection<ModelRecord>;
	readonly encryptionKeys: ReadonlyMap<string, DataEncryptionKey>;
	readonly activeEncryptionKey: DataEncryptionKey;
	readonly identityIndexKey: IndexHmacKey;
	readonly crypto?: Crypto;
}

export type CustomerMappingResult =
	| { readonly kind: 'mapped'; readonly record: CustomerMappingRecord }
	| { readonly kind: 'not_verified' | 'conflict' | 'unavailable' | 'invalid' };

/**
 * Repair one derived customer association from a durable, verified payment. This bounded
 * single-record stage makes no provider call and is deliberately separate from paid/result CAS.
 */
export async function repairVerifiedCustomerMapping(
	input: RepairCustomerMappingInput,
	dependencies: CustomerMappingDependencies,
): Promise<CustomerMappingResult> {
	if (!input || typeof input.pluginId !== 'string' || input.pluginId.length < 1 ||
		typeof input.intentId !== 'string' || !INTENT_ID.test(input.intentId) ||
		!Number.isSafeInteger(input.nowMs) || input.nowMs < 0 || !Number.isFinite(new Date(input.nowMs).getTime())) {
		return { kind: 'invalid' };
	}
	const candidate = input.intent;
	if (!isAdmissionIntentRecord(candidate) || !isProviderIntentRecord(candidate) || candidate.identityHmac !== input.intentId) {
		return { kind: 'unavailable' };
	}
	const intent = candidate as unknown as Record<string, unknown>;
	if (intent.state !== 'verified_paid') return { kind: 'not_verified' };
	const verified = verifiedCustomerSource(intent);
	if (!verified) return { kind: 'unavailable' };
	let snapshot: AdmittedPaymentSnapshot;
	try {
		snapshot = await decryptValue<AdmittedPaymentSnapshot>(intent.protectedSnapshot, dependencies.encryptionKeys, {
			pluginId: input.pluginId,
			collection: 'intents',
			recordId: input.intentId,
			schemaVersion: 1,
			purpose: 'custom_fields',
		}, dependencies.crypto ?? globalThis.crypto);
	} catch {
		return { kind: 'unavailable' };
	}
	if (!isTrustedSnapshot(snapshot, intent)) return { kind: 'unavailable' };
	const email = requiredPayerEmail(snapshot);
	if (!email) return { kind: 'unavailable' };
	const profileId = snapshot.merchantProfile;
	const environment = snapshot.environment;
	let recordId: string;
	let subjectCorrelationId: string;
	try {
		const scopedSubject = [snapshot.siteId, snapshot.subject.kind, snapshot.subject.id, profileId, environment];
		const customerDigest = await hmacIndex(['paystack-customer-map-v1', ...scopedSubject], dependencies.identityIndexKey,
			dependencies.crypto ?? globalThis.crypto);
		const subjectDigest = await hmacIndex(['paystack-customer-subject-v1', ...scopedSubject], dependencies.identityIndexKey,
			dependencies.crypto ?? globalThis.crypto);
		recordId = deterministicRecordId('customers', customerDigest);
		subjectCorrelationId = `psk:v1:subjects:${subjectDigest}`;
	} catch {
		return { kind: 'unavailable' };
	}
	const now = new Date(input.nowMs).toISOString();
	const existing = await readCustomerRecord(dependencies.customers, recordId);
	if (existing.kind === 'unavailable') return { kind: 'unavailable' };
	if (existing.kind === 'found') {
		const current = existing.record;
		if (current.providerCustomerId !== verified.providerCustomerId ||
			current.subjectCorrelationId !== subjectCorrelationId || current.profileId !== profileId ||
			current.environment !== environment || current.customerCorrelationId !== recordId) {
			return { kind: 'conflict' };
		}
		let priorEmail: string;
		try {
			priorEmail = await decryptValue<string>(current.encryptedEmail, dependencies.encryptionKeys, {
				pluginId: input.pluginId, collection: 'customers', recordId, schemaVersion: 1, purpose: 'payer_email',
			}, dependencies.crypto ?? globalThis.crypto);
		} catch {
			return { kind: 'unavailable' };
		}
		if (typeof priorEmail !== 'string' || !isEmail(priorEmail)) return { kind: 'unavailable' };
		if (!isCanonicalTimestamp(current.emailVerifiedAt)) return { kind: 'unavailable' };
		if (verified.result.verifiedAt < current.emailVerifiedAt) return { kind: 'mapped', record: current };
		if (verified.result.verifiedAt === current.emailVerifiedAt && !sameEmail(priorEmail, email)) return { kind: 'conflict' };
		if (sameEmail(priorEmail, email) && verified.result.verifiedAt === current.emailVerifiedAt) {
			return { kind: 'mapped', record: current };
		}
		if (sameEmail(priorEmail, email)) {
			const updated: CustomerMappingRecord = { ...current, emailVerifiedAt: verified.result.verifiedAt, updatedAt: now };
			return writeMapping(dependencies, recordId, existing.revision, updated, email, input.pluginId);
		}
		let encryptedEmail: AesGcmEnvelope;
		try {
			encryptedEmail = await encryptValue(email, dependencies.activeEncryptionKey, {
				pluginId: input.pluginId, collection: 'customers', recordId, schemaVersion: 1, purpose: 'payer_email',
			}, dependencies.crypto ?? globalThis.crypto);
		} catch {
			return { kind: 'unavailable' };
		}
		const updated: CustomerMappingRecord = { ...current, encryptedEmail, emailVerifiedAt: verified.result.verifiedAt, updatedAt: now };
		return writeMapping(dependencies, recordId, existing.revision, updated, email, input.pluginId);
	}
	let encryptedEmail: AesGcmEnvelope;
	try {
		encryptedEmail = await encryptValue(email, dependencies.activeEncryptionKey, {
			pluginId: input.pluginId, collection: 'customers', recordId, schemaVersion: 1, purpose: 'payer_email',
		}, dependencies.crypto ?? globalThis.crypto);
	} catch {
		return { kind: 'unavailable' };
	}
	const created: CustomerMappingRecord = {
		modelVersion: 1,
		customerCorrelationId: recordId,
		subjectCorrelationId,
		providerCustomerId: verified.providerCustomerId,
		profileId,
		environment,
		mappingState: 'mapped',
		encryptedEmail,
		emailVerifiedAt: verified.result.verifiedAt,
		createdAt: verified.result.verifiedAt,
		updatedAt: now,
	};
	return writeMapping(dependencies, recordId, null, created, email, input.pluginId);
}

function verifiedCustomerSource(intent: Record<string, unknown>): { readonly result: VerifiedPaymentResult; readonly providerCustomerId: string } | null {
	if (intent.state !== 'verified_paid' || intent.verificationState !== 'matched' ||
		!isCanonicalTimestamp(intent.verifiedAt) || !isPlainObject(intent.providerObservation) ||
		intent.providerObservation.status !== 'success' ||
		typeof intent.providerObservation.providerCustomerId !== 'string' ||
		!PROVIDER_CUSTOMER_ID.test(intent.providerObservation.providerCustomerId) ||
		!isPlainObject(intent.receipt) || intent.receipt.provider !== 'paystack' || intent.receipt.status !== 'success') return null;
	const result = intent.resultEvent;
	if (!isVerifiedPaymentResult(result) || result.intentId !== intent.identityHmac || result.verifiedAt !== intent.verifiedAt ||
		result.merchantProfile !== intent.merchantProfile || result.environment !== intent.environment ||
		intent.resultEventId !== result.eventId || intent.receipt.providerReference !== result.providerReference ||
		intent.receipt.providerResourceId !== result.providerResourceId ||
		intent.providerObservation.providerReference !== result.providerReference ||
		intent.providerObservation.providerResourceId !== result.providerResourceId) return null;
	if (!Array.isArray(intent.attempts)) return null;
	const currentAttempt = intent.attempts.find((attempt: unknown) => isPlainObject(attempt) && attempt.id === intent.currentAttemptId);
	if (!currentAttempt || currentAttempt.state !== 'succeeded' || currentAttempt.providerState !== 'success' ||
		currentAttempt.providerReference !== result.providerReference || currentAttempt.providerResourceId !== result.providerResourceId) return null;
	return { result, providerCustomerId: intent.providerObservation.providerCustomerId };
}

function isTrustedSnapshot(snapshot: unknown, intent: Record<string, unknown>): snapshot is AdmittedPaymentSnapshot {
	return isPlainObject(snapshot) && snapshot.schemaVersion === '1.0' && typeof snapshot.siteId === 'string' &&
		isPlainObject(snapshot.subject) && (snapshot.subject.kind === 'guest' || snapshot.subject.kind === 'member') &&
		isSafeIdentityPart(snapshot.siteId) && isSafeIdentityPart(snapshot.subject.id) &&
		isSafeIdentityPart(snapshot.merchantProfile) &&
		snapshot.siteId === intent.siteId && snapshot.merchantProfile === intent.merchantProfile &&
		snapshot.environment === intent.environment && snapshot.credentialVersion === intent.credentialVersion;
}

function requiredPayerEmail(snapshot: AdmittedPaymentSnapshot): string | null {
	const form = validateFormDefinition(snapshot.form);
	if (!form.ok) return null;
	const fields = validateFieldValues(form.value, snapshot.fields);
	if (!fields.ok) return null;
	const emailFields = form.value.fields.filter((field) => field.type === 'email');
	if (emailFields.length !== 1) return null;
	const email = fields.value[emailFields[0]!.id];
	return typeof email === 'string' && isEmail(email) ? email : null;
}

async function readCustomerRecord(
	collection: VersionedCollection<ModelRecord>, recordId: string,
): Promise<{ readonly kind: 'missing' } | { readonly kind: 'found'; readonly record: CustomerMappingRecord; readonly revision: string } | { readonly kind: 'unavailable' }> {
	try {
		const item = await collection.getVersioned(recordId);
		if (!item) return { kind: 'missing' };
		if (!item.revision || !isCustomerMappingRecord(item.value, recordId)) return { kind: 'unavailable' };
		assertSupportedRecord(item.value);
		return { kind: 'found', record: item.value, revision: item.revision };
	} catch {
		return { kind: 'unavailable' };
	}
}

async function writeMapping(
	dependencies: CustomerMappingDependencies,
	recordId: string,
	expectedRevision: string | null,
	wanted: CustomerMappingRecord,
	wantedEmail: string,
	pluginId: string,
): Promise<CustomerMappingResult> {
	try {
		assertSupportedRecord(wanted);
		const result = await dependencies.customers.compareAndSet(recordId, expectedRevision, wanted);
		if (result.applied && result.revision) return { kind: 'mapped', record: wanted };
	} catch {
		// A storage bridge rejection can follow a committed write. Confirm it with one exact read.
	}
	const observed = await readCustomerRecord(dependencies.customers, recordId);
	if (observed.kind === 'unavailable') return { kind: 'unavailable' };
	if (observed.kind === 'missing') return { kind: 'conflict' };
	if (observed.record.providerCustomerId !== wanted.providerCustomerId ||
		observed.record.subjectCorrelationId !== wanted.subjectCorrelationId ||
		observed.record.profileId !== wanted.profileId || observed.record.environment !== wanted.environment) {
		return { kind: 'conflict' };
	}
	try {
		const email = await decryptValue<string>(observed.record.encryptedEmail, dependencies.encryptionKeys, {
			pluginId, collection: 'customers', recordId, schemaVersion: 1, purpose: 'payer_email',
		}, dependencies.crypto ?? globalThis.crypto);
		return typeof email === 'string' && sameEmail(email, wantedEmail)
			? { kind: 'mapped', record: observed.record }
			: { kind: 'conflict' };
	} catch {
		return { kind: 'unavailable' };
	}
}

function isCustomerMappingRecord(value: unknown, recordId: string): value is CustomerMappingRecord {
	if (!isPlainObject(value) || value.modelVersion !== 1 || value.customerCorrelationId !== recordId ||
		!CUSTOMER_CORRELATION_ID.test(recordId) || typeof value.subjectCorrelationId !== 'string' ||
		!/^psk:v1:subjects:[a-f0-9]{64}$/u.test(value.subjectCorrelationId) ||
		typeof value.providerCustomerId !== 'string' || !PROVIDER_CUSTOMER_ID.test(value.providerCustomerId) ||
		typeof value.profileId !== 'string' || value.profileId.length < 1 ||
		(value.environment !== 'test' && value.environment !== 'live') || value.mappingState !== 'mapped' ||
		!isEncryptedEnvelope(value.encryptedEmail) || !isCanonicalTimestamp(value.createdAt) || !isCanonicalTimestamp(value.updatedAt)) return false;
	const expectedKeys = ['modelVersion', 'customerCorrelationId', 'subjectCorrelationId', 'providerCustomerId', 'profileId',
		'environment', 'mappingState', 'encryptedEmail', 'emailVerifiedAt', 'createdAt', 'updatedAt'];
	return isCanonicalTimestamp(value.emailVerifiedAt) &&
		Object.keys(value).length === expectedKeys.length && expectedKeys.every((key) => Object.hasOwn(value, key));
}

function isEncryptedEnvelope(value: unknown): value is AesGcmEnvelope {
	return isPlainObject(value) && value.version === 1 && value.algorithm === 'A256GCM' &&
		typeof value.keyId === 'string' && typeof value.iv === 'string' && typeof value.ciphertext === 'string';
}

function isEmail(value: string): boolean {
	return value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(value);
}

function sameEmail(a: string, b: string): boolean {
	return a.trim().toLowerCase() === b.trim().toLowerCase();
}

function isSafeIdentityPart(value: unknown): value is string {
	return typeof value === 'string' && value.length > 0 &&
		new TextEncoder().encode(value).byteLength <= 1_024 && !/[\u0000-\u001f\u007f]/u.test(value);
}

function isCanonicalTimestamp(value: unknown): value is string {
	if (typeof value !== 'string') return false;
	const ms = Date.parse(value);
	return Number.isFinite(ms) && new Date(ms).toISOString() === value;
}
