import { approvedExamples } from './spec-fixtures.js';
import { encodeBase64Url, encryptValue, createDataEncryptionKey } from '../../src/security/encryption.js';
import type { AdmittedPaymentSnapshot } from '../../src/storage/admission.js';
import type { SettingsPort } from '../../src/domain/configuration.js';
import type { ModelRecord, VersionedCollection } from '../../src/storage/schema.js';

export const NOW = Date.parse('2026-10-18T10:00:00.000Z');
export const INTENT_ID = `psk:v1:intents:${'1'.repeat(64)}`;
export const ATTEMPT_ID = `psk:v1:attempts:${'2'.repeat(64)}`;
export const REFERENCE = 'psk-test-reference-1';
export const SECRET = 'sk_test_paystack_test_only';

export function successData(): Record<string, unknown> {
	return {
		id: 4099260516,
		domain: 'test',
		status: 'success',
		reference: REFERENCE,
		amount: 500000,
		requested_amount: 500000,
		fees: 0,
		currency: 'NGN',
		channel: 'card',
		customer: { id: 1001, email: 'payer@example.test' },
	};
}

export async function createVerificationFixture(options: {
	provider?: Record<string, unknown>;
	initialState?: string;
	priorPaid?: boolean;
	verificationCount?: number;
	failAfterApply?: boolean;
	beforeCas?: (store: MemoryIntentCollection) => Promise<void>;
} = {}) {
	const fieldMaterial = new Uint8Array(32).fill(11);
	const identityMaterial = new Uint8Array(32).fill(22);
	const fieldKey = createDataEncryptionKey('field-v1', fieldMaterial);
	const snapshot: AdmittedPaymentSnapshot = {
		schemaVersion: '1.0', siteId: 'site_1', subject: { kind: 'member', id: 'member_1' }, businessReference: 'order_1',
		merchantProfile: 'merchant_1', environment: 'test', credentialVersion: 1,
		form: approvedExamples.fixedForm,
		amount: { currency: 'NGN', value: '5000.00', minorUnits: 500000 },
		fields: { payer_email: 'payer@example.test' }, metadata: {},
	};
	const encrypted = await encryptValue(snapshot, fieldKey, {
		pluginId: 'did:plc:publisher/paystack-payments', collection: 'intents', recordId: INTENT_ID, schemaVersion: 1, purpose: 'custom_fields',
	});
	const at = new Date(NOW - 60_000).toISOString();
	const priorReceipt = { provider: 'paystack', status: 'success', providerResourceId: '4099260516', providerReference: REFERENCE,
		amount: { currency: 'NGN', value: '5000.00' }, domain: 'test', channel: 'card', verifiedAt: at };
	const priorResult = {
		schemaVersion: '1.0', eventId: `psk:v1:results:${'a'.repeat(64)}`, type: 'payment.verified', paymentId: INTENT_ID,
		intentId: INTENT_ID, attemptId: ATTEMPT_ID, formId: 'example_variable_payment', formRevision: '1', provider: 'paystack',
		environment: 'test', merchantProfile: 'merchant_1', amount: { currency: 'NGN', value: '5000.00' },
		verifiedAt: at, providerResourceId: '4099260516', providerReference: REFERENCE,
	};
	const attempt = {
		modelVersion: 1, id: ATTEMPT_ID, ordinal: 1, predecessorId: null,
		state: options.priorPaid ? 'succeeded' : 'initializing',
		providerState: options.priorPaid ? 'success' : 'create_started', credentialVersion: 1,
		createTransmissionStarted: true, providerReference: REFERENCE,
		providerResourceId: options.priorPaid ? '4099260516' : null,
		...(options.verificationCount !== undefined ? { verificationCount: options.verificationCount } : {}),
		createdAt: at, updatedAt: at, nextRunAt: NOW,
	};
	const intent = {
		modelVersion: 1, siteId: 'site_1', merchantId: 'merchant_1', merchantProfile: 'merchant_1', environment: 'test',
		credentialVersion: 1, formId: 'example_variable_payment', formRevision: '1', identityHmac: INTENT_ID,
		fingerprintHmac: 'b'.repeat(64), state: options.initialState ?? 'initializing',
		deliveryState: options.priorPaid ? 'pending' : 'not_eligible', currentAttemptId: ATTEMPT_ID, attempts: [attempt],
		protectedSnapshot: encrypted, leaseEpoch: 1, nextRunAt: NOW, createdAt: at, updatedAt: at,
		...(options.priorPaid ? { verifiedAt: at, receipt: priorReceipt, resultEvent: priorResult, resultEventId: priorResult.eventId } : {}),
	};
	const intents = new MemoryIntentCollection(intent as unknown as ModelRecord, options.beforeCas, options.failAfterApply ?? false);
	const configuration = {
		schemaVersion: 1, paused: true, activeProfile: 'merchant_1',
		profiles: { merchant_1: { profileId: 'merchant_1', activeCredentialVersion: 1,
			credentialVersions: [{ version: 1, environment: 'test', secretKey: SECRET }] } },
		integrationKeys: [],
		fieldEncryptionKeyRing: { activeKeyId: 'field-v1', keys: [{ keyId: 'field-v1', material: encodeBase64Url(fieldMaterial) }] },
		identityHmacKeyRing: { activeKeyId: 'identity-v1', keys: [{ keyId: 'identity-v1', material: encodeBase64Url(identityMaterial) }] },
	};
	const settings: SettingsPort = {
		getVersioned: async <T>() => ({ value: JSON.stringify(configuration) as T, revision: 'settings-r1' }),
		compareAndSet: async () => ({ applied: false }),
	};
	const fetches: Array<{ url: string; init?: RequestInit }> = [];
	const fetch = async (url: string, init?: RequestInit) => {
		fetches.push(init ? { url, init } : { url });
		return new Response(JSON.stringify({ status: true, message: 'Verification successful', data: options.provider ?? successData() }), {
			status: 200, headers: { 'content-type': 'application/json' },
		});
	};
	return {
		dependencies: { pluginId: 'did:plc:publisher/paystack-payments', settings, intents, fetch, now: () => NOW },
		intents, fetches, priorReceipt, priorResult,
	};
}

class MemoryIntentCollection implements VersionedCollection<ModelRecord> {
	value: ModelRecord | null;
	revision = 'r1';
	writeCount = 0;
	private beforeCas: ((store: MemoryIntentCollection) => Promise<void>) | undefined;
	private failAfterApply: boolean;
	constructor(value: ModelRecord, beforeCas?: (store: MemoryIntentCollection) => Promise<void>, failAfterApply = false) {
		this.value = value;
		this.beforeCas = beforeCas;
		this.failAfterApply = failAfterApply;
	}
	async getVersioned(): Promise<{ value: ModelRecord; revision: string } | null> {
		return this.value ? { value: this.value, revision: this.revision } : null;
	}
	async compareAndSet(_id: string, expectedRevision: string | null, value: ModelRecord): Promise<{ applied: true; revision: string } | { applied: false }> {
		await this.beforeCas?.(this);
		this.beforeCas = undefined;
		if (expectedRevision !== this.revision) return { applied: false };
		this.value = value;
		this.revision = `r${++this.writeCount + 1}`;
		if (this.failAfterApply) { this.failAfterApply = false; throw new Error('HOST_RESPONSE_LOST_AFTER_APPLY'); }
		return { applied: true, revision: this.revision };
	}
	async compareAndDelete(): Promise<{ applied: boolean }> { return { applied: false }; }
	async query(_options?: { where?: Record<string, unknown> }): Promise<{ items: Array<{ id: string; data: ModelRecord }>; hasMore: boolean }> { return { items: [], hasMore: false }; }
}
