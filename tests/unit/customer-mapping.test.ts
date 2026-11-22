import { describe, expect, it } from 'vite-plus/test';
import { approvedExamples } from '../support/spec-fixtures.js';
import { createDataEncryptionKey, createIndexHmacKey, decryptValue, encodeBase64Url, encryptValue } from '../../src/security/encryption.js';
import { createVerifiedPaymentResult } from '../../src/domain/result.js';
import type { AdmittedPaymentSnapshot } from '../../src/storage/admission.js';
import { repairVerifiedCustomerMapping } from '../../src/storage/customers.js';
import type { ModelRecord, VersionedCollection } from '../../src/storage/schema.js';

const NOW = Date.parse('2026-10-18T11:00:00.000Z');
const INTENT_ID = `psk:v1:intents:${'1'.repeat(64)}`;
const ATTEMPT_ID = `psk:v1:attempts:${'2'.repeat(64)}`;
const PLUGIN_ID = 'did:plc:publisher/paystack-payments';
const PROVIDER_CUSTOMER_ID = '9007199254740993';

describe('verified customer mapping repair', () => {
	it('stores only the lossless provider ID and encrypted required email under trusted subject/profile/environment', async () => {
		const fixture = await createFixture();
		const result = await repairVerifiedCustomerMapping(fixture.input, fixture.dependencies);
		expect(result.kind).toBe('mapped');
		if (result.kind !== 'mapped') return;
		expect(result.record).toMatchObject({
			providerCustomerId: PROVIDER_CUSTOMER_ID,
			profileId: 'merchant_1',
			environment: 'test',
			mappingState: 'mapped',
		});
		expect(result.record.customerCorrelationId).toMatch(/^psk:v1:customers:[a-f0-9]{64}$/u);
		expect(result.record.subjectCorrelationId).toMatch(/^psk:v1:subjects:[a-f0-9]{64}$/u);
		const serialized = JSON.stringify(result.record);
		expect(serialized).not.toContain('payer@example.test');
		expect(serialized).not.toContain('member_1');
		expect(serialized).not.toContain('site_1');
		expect(fixture.customers.casCount).toBe(1);
		expect(fixture.customers.queryCount).toBe(0);
	});

	it('refuses pending and review-only transactions without writing customer data', async () => {
		for (const state of ['pending', 'review_required']) {
			const fixture = await createFixture({ intentPatch: { state } });
			const result = await repairVerifiedCustomerMapping(fixture.input, fixture.dependencies);
			expect(result.kind).toBe('not_verified');
			expect(fixture.customers.casCount).toBe(0);
		}
	});

	it('does not claim a customer mapping when the trusted snapshot disagrees with the paid aggregate', async () => {
		const fixture = await createFixture({ intentPatch: { merchantProfile: 'merchant_other' } });
		const result = await repairVerifiedCustomerMapping(fixture.input, fixture.dependencies);
		expect(result.kind).toBe('unavailable');
		expect(fixture.customers.casCount).toBe(0);
	});

	it('leaves a verified payment unmapped when the provider response contains no customer ID', async () => {
		const fixture = await createFixture({ intentPatch: { providerObservation: {
			status: 'success', providerReference: 'psk-reference-1', providerResourceId: '4099260516', observedAt: new Date(NOW).toISOString(),
		} } });
		const result = await repairVerifiedCustomerMapping(fixture.input, fixture.dependencies);
		expect(result.kind).toBe('unavailable');
		expect(fixture.customers.casCount).toBe(0);
	});

	it('never rebinds a stable trusted subject to a different provider customer ID', async () => {
		const fixture = await createFixture();
		const first = await repairVerifiedCustomerMapping(fixture.input, fixture.dependencies);
		expect(first.kind).toBe('mapped');
		const changed = { ...fixture.input, intent: { ...fixture.intent, providerObservation: {
			...fixture.intent.providerObservation as Record<string, unknown>, providerCustomerId: '1002',
		} } };
		const result = await repairVerifiedCustomerMapping(changed, fixture.dependencies);
		expect(result.kind).toBe('conflict');
		expect(fixture.customers.casCount).toBe(1);
	});

	it('updates the encrypted required email only from another verified payment for the same subject', async () => {
		const first = await createFixture();
		const created = await repairVerifiedCustomerMapping(first.input, first.dependencies);
		expect(created.kind).toBe('mapped');
		const next = await createFixture({ email: 'new-payer@example.test', verifiedAt: new Date(NOW).toISOString() });
		next.dependencies.customers = first.customers;
		const updated = await repairVerifiedCustomerMapping(next.input, next.dependencies);
		expect(updated.kind).toBe('mapped');
		if (updated.kind !== 'mapped') return;
		const plaintext = await decryptValue<string>(updated.record.encryptedEmail, first.dependencies.encryptionKeys, {
			pluginId: PLUGIN_ID, collection: 'customers', recordId: updated.record.customerCorrelationId,
			schemaVersion: 1, purpose: 'payer_email',
		});
		expect(plaintext).toBe('new-payer@example.test');
		expect(first.customers.casCount).toBe(2);
	});

	it('does not let a delayed older repair replace email from a newer verified payment', async () => {
		const newest = await createFixture({ email: 'newest@example.test', verifiedAt: new Date(NOW).toISOString() });
		const first = await repairVerifiedCustomerMapping(newest.input, newest.dependencies);
		expect(first.kind).toBe('mapped');
		const older = await createFixture({ email: 'older@example.test', verifiedAt: new Date(NOW - 120_000).toISOString() });
		older.dependencies.customers = newest.customers;
		const result = await repairVerifiedCustomerMapping(older.input, older.dependencies);
		expect(result.kind).toBe('mapped');
		if (result.kind !== 'mapped') return;
		const email = await decryptValue<string>(result.record.encryptedEmail, newest.dependencies.encryptionKeys, {
			pluginId: PLUGIN_ID, collection: 'customers', recordId: result.record.customerCorrelationId,
			schemaVersion: 1, purpose: 'payer_email',
		});
		expect(email).toBe('newest@example.test');
		expect(newest.customers.casCount).toBe(1);
	});

	it('confirms one applied CAS after the host loses its response without retrying the write', async () => {
		const fixture = await createFixture({ loseFirstResponse: true });
		const result = await repairVerifiedCustomerMapping(fixture.input, fixture.dependencies);
		expect(result.kind).toBe('mapped');
		expect(fixture.customers.casCount).toBe(1);
		expect(fixture.customers.readCount).toBe(2);
	});

	it('keeps customer mappings separate by merchant profile and environment', async () => {
		const testFixture = await createFixture();
		const testResult = await repairVerifiedCustomerMapping(testFixture.input, testFixture.dependencies);
		const liveFixture = await createFixture({ profileId: 'merchant_1', environment: 'live' });
		const liveResult = await repairVerifiedCustomerMapping(liveFixture.input, liveFixture.dependencies);
		expect(testResult.kind).toBe('mapped');
		expect(liveResult.kind).toBe('mapped');
		if (testResult.kind === 'mapped' && liveResult.kind === 'mapped') {
			expect(testResult.record.customerCorrelationId).not.toBe(liveResult.record.customerCorrelationId);
		}
	});
});

async function createFixture(options: {
	email?: string;
	verifiedAt?: string;
	profileId?: string;
	environment?: 'test' | 'live';
	intentPatch?: Record<string, unknown>;
	loseFirstResponse?: boolean;
} = {}) {
	const fieldMaterial = new Uint8Array(32).fill(11);
	const identityMaterial = new Uint8Array(32).fill(22);
	const fieldKey = createDataEncryptionKey('field-v1', fieldMaterial);
	const identityKey = createIndexHmacKey('identity-v1', identityMaterial);
	const profileId = options.profileId ?? 'merchant_1';
	const environment = options.environment ?? 'test';
	const form = structuredClone(approvedExamples.fixedForm) as Record<string, unknown>;
	const snapshot: AdmittedPaymentSnapshot = {
		schemaVersion: '1.0', siteId: 'site_1', subject: { kind: 'member', id: 'member_1' }, businessReference: 'order_1',
		merchantProfile: profileId, environment, credentialVersion: 1,
		form,
		amount: { currency: 'NGN', value: '5000.00', minorUnits: 500000 },
		fields: { payer_email: options.email ?? 'payer@example.test' }, metadata: {},
	};
	const protectedSnapshot = await encryptValue(snapshot, fieldKey, {
		pluginId: PLUGIN_ID, collection: 'intents', recordId: INTENT_ID, schemaVersion: 1, purpose: 'custom_fields',
	});
	const verifiedAt = options.verifiedAt ?? new Date(NOW - 60_000).toISOString();
	const resultEvent = await createVerifiedPaymentResult({
		intentId: INTENT_ID, attemptId: ATTEMPT_ID, formId: 'example_variable_payment', formRevision: '1',
		environment, merchantProfile: profileId, amount: { currency: 'NGN', value: '5000.00' }, verifiedAt,
		providerResourceId: '4099260516', providerReference: 'psk-reference-1',
	});
	const intent: ModelRecord = {
		modelVersion: 1, siteId: 'site_1', merchantId: profileId, merchantProfile: profileId, environment,
		credentialVersion: 1, formId: 'example_variable_payment', formRevision: '1', identityHmac: INTENT_ID,
		fingerprintHmac: 'b'.repeat(64), state: 'verified_paid', verificationState: 'matched',
		deliveryState: 'pending', currentAttemptId: ATTEMPT_ID,
		attempts: [{ modelVersion: 1, id: ATTEMPT_ID, ordinal: 1, predecessorId: null, state: 'succeeded',
			providerState: 'success', credentialVersion: 1, createTransmissionStarted: true,
			providerReference: 'psk-reference-1', providerResourceId: '4099260516', createdAt: verifiedAt,
			updatedAt: verifiedAt, nextRunAt: Number.MAX_SAFE_INTEGER }],
		protectedSnapshot, leaseEpoch: 1, nextRunAt: Number.MAX_SAFE_INTEGER,
		verifiedAt, resultEvent, resultEventId: resultEvent.eventId,
		receipt: { provider: 'paystack', status: 'success', providerReference: 'psk-reference-1',
			providerResourceId: '4099260516', amount: { currency: 'NGN', value: '5000.00' } },
		providerObservation: { status: 'success', providerCustomerId: PROVIDER_CUSTOMER_ID,
			providerReference: 'psk-reference-1', providerResourceId: '4099260516', observedAt: verifiedAt },
		createdAt: verifiedAt, updatedAt: verifiedAt,
		...options.intentPatch,
	};
	const customers = new MemoryCustomerCollection(options.loseFirstResponse ?? false);
	const encryptionKeys = new Map([[fieldKey.keyId, fieldKey]]);
	return {
		intent,
		input: { pluginId: PLUGIN_ID, intentId: INTENT_ID, intent, nowMs: NOW },
		customers,
		dependencies: { customers, encryptionKeys, activeEncryptionKey: fieldKey, identityIndexKey: identityKey },
	};
}

class MemoryCustomerCollection implements VersionedCollection<ModelRecord> {
	private readonly items = new Map<string, { value: ModelRecord; revision: string }>();
	casCount = 0;
	readCount = 0;
	queryCount = 0;
	private loseFirstResponse: boolean;

	constructor(loseFirstResponse = false) { this.loseFirstResponse = loseFirstResponse; }

	async getVersioned(id: string): Promise<{ value: ModelRecord; revision: string } | null> {
		this.readCount += 1;
		const item = this.items.get(id);
		return item ? { value: item.value, revision: item.revision } : null;
	}

	async compareAndSet(id: string, expectedRevision: string | null, data: ModelRecord): Promise<{ applied: true; revision: string } | { applied: false }> {
		this.casCount += 1;
		const current = this.items.get(id);
		if ((current?.revision ?? null) !== expectedRevision) return { applied: false };
		const revision = `r${this.casCount}`;
		this.items.set(id, { value: data, revision });
		if (this.loseFirstResponse) { this.loseFirstResponse = false; throw new Error('HOST_RESPONSE_LOST_AFTER_APPLY'); }
		return { applied: true, revision };
	}

	async compareAndDelete(): Promise<{ applied: boolean }> { return { applied: false }; }
	async query(): Promise<{ items: Array<{ id: string; data: ModelRecord }>; hasMore: boolean }> {
		this.queryCount += 1;
		return { items: [], hasMore: false };
	}
}
