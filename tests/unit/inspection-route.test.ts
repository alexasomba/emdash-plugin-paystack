import { describe, expect, it } from 'vite-plus/test';
import { handleInspection, type InspectionDependencies } from '../../src/routes/inspection.js';
import { CONFIGURATION_SCHEMA_VERSION, type StoredPaymentConfiguration } from '../../src/domain/configuration.js';
import { createDataEncryptionKey, createIndexHmacKey, encodeBase64Url, encryptValue, hmacIndex } from '../../src/security/encryption.js';
import { deterministicRecordId, type ModelRecord, type VersionedCollection } from '../../src/storage/schema.js';

const PLUGIN_ID = 'paystack-payments';
const PROFILE_ID = 'merchant_profile_1';
const SITE_URL = 'https://cms.example.test/admin';
const NOW = Date.parse('2026-10-18T10:00:00.000Z');
const INTENT_ID = `psk:v1:intents:${'a'.repeat(64)}`;
const ATTEMPT_ID = `psk:v1:attempts:${'b'.repeat(64)}`;
const identityKey = createIndexHmacKey('identity-v1', new Uint8Array(32).fill(7));
const fieldKey = createDataEncryptionKey('field-v1', new Uint8Array(32).fill(8));

function configuration(): StoredPaymentConfiguration {
	return {
		schemaVersion: CONFIGURATION_SCHEMA_VERSION,
		paused: false,
		activeProfile: PROFILE_ID,
		profiles: {
			[PROFILE_ID]: {
				profileId: PROFILE_ID,
				activeCredentialVersion: 1,
				credentialVersions: [{ version: 1, environment: 'test', secretKey: 'sk_test_synthetic_secret' }],
			},
		},
		integrationKeys: [],
		fieldEncryptionKeyRing: { activeKeyId: fieldKey.keyId, keys: [{ keyId: fieldKey.keyId, material: encodeBase64Url(fieldKey.material) }] },
		identityHmacKeyRing: { activeKeyId: identityKey.keyId, keys: [{ keyId: identityKey.keyId, material: encodeBase64Url(identityKey.material) }] },
	};
}

function rows<T extends ModelRecord>(input: {
	readonly items?: readonly { readonly id: string; readonly data: T }[];
	readonly cursor?: string;
	readonly hasMore?: boolean;
	readonly onQuery?: (options: Parameters<VersionedCollection<T>['query']>[0]) => void;
} = {}): VersionedCollection<T> {
	return {
		getVersioned: async (id) => input.items?.find((item) => item.id === id)
			? { value: input.items.find((item) => item.id === id)!.data, revision: 'revision-1' } : null,
		compareAndSet: async () => ({ applied: false }),
		compareAndDelete: async () => ({ applied: false }),
		query: async (options) => {
			input.onQuery?.(options);
			return { items: [...(input.items ?? [])], ...(input.cursor ? { cursor: input.cursor } : {}), hasMore: input.hasMore ?? false };
		},
	};
}

function dependencies(options: {
	readonly intents?: VersionedCollection<ModelRecord>;
	readonly customers?: VersionedCollection<ModelRecord>;
	readonly inbox?: VersionedCollection<ModelRecord>;
	readonly siteUrl?: string;
} = {}): InspectionDependencies {
	const storedConfiguration = JSON.stringify(configuration());
	return {
		pluginId: PLUGIN_ID,
		siteUrl: options.siteUrl ?? SITE_URL,
		settings: {
			getVersioned: async <T>() => ({ value: storedConfiguration as T, revision: 'settings-1' }),
			compareAndSet: async () => ({ applied: false }),
		},
		intents: options.intents ?? rows(),
		customers: options.customers ?? rows(),
		inbox: options.inbox ?? rows(),
		now: () => NOW,
	};
}

function admittedIntent(protectedSnapshot: unknown, state = 'pending'): ModelRecord {
	return {
		modelVersion: 1,
		siteId: 'frontend_site_1',
		merchantId: PROFILE_ID,
		merchantProfile: PROFILE_ID,
		environment: 'test',
		credentialVersion: 1,
		formId: 'membership_dues',
		formRevision: '3',
		identityHmac: INTENT_ID,
		fingerprintHmac: 'c'.repeat(64),
		state,
		deliveryState: 'not_eligible',
		currentAttemptId: ATTEMPT_ID,
		attempts: [{
			modelVersion: 1,
			id: ATTEMPT_ID,
			ordinal: 1,
			predecessorId: null,
			state: state === 'pending' ? 'pending' : 'requires_action',
			providerState: 'initialized',
			credentialVersion: 1,
			createTransmissionStarted: true,
			providerReference: 'provider-reference-private',
			providerResourceId: null,
			createdAt: '2026-10-18T09:00:00.000Z',
			updatedAt: '2026-10-18T09:01:00.000Z',
			nextRunAt: NOW + 60_000,
		}],
		protectedSnapshot,
		leaseEpoch: 1,
		nextRunAt: NOW + 60_000,
		createdAt: '2026-10-18T09:00:00.000Z',
		updatedAt: '2026-10-18T09:01:00.000Z',
	};
}

async function encryptSnapshot(intentId = INTENT_ID): Promise<Record<string, unknown>> {
	const value = {
		schemaVersion: '1.0',
		siteId: 'frontend_site_1',
		subject: { kind: 'member', id: 'member_9' },
		businessReference: 'private-order-reference',
		merchantProfile: PROFILE_ID,
		environment: 'test',
		credentialVersion: 1,
		form: { id: 'membership_dues', revision: '3' },
		amount: { currency: 'NGN', value: '2500.00', minorUnits: 250000 },
		fields: { payer_email: 'payer@example.test', note: 'private custom field' },
		metadata: { campaign: 'private metadata' },
	};
	return await encryptValue(value, fieldKey, {
		pluginId: PLUGIN_ID,
		collection: 'intents',
		recordId: intentId,
		schemaVersion: 1,
		purpose: 'custom_fields',
	}) as unknown as Record<string, unknown>;
}

describe('private payment inspection route', () => {
	it('validates view-specific exact filters and binds the host cursor to its full scope', async () => {
		let calls = 0;
		let receivedCursor: string | undefined;
		const source = rows<ModelRecord>({
			hasMore: true,
			cursor: 'host-page-2',
			onQuery: (options) => { calls += 1; receivedCursor = options?.cursor; },
		});
		const deps = dependencies({ intents: source });
		const input = { view: 'payments', filter: 'pending', sort: 'createdAt:desc', limit: 5 };
		const first = await handleInspection(input, deps);
		expect(first).toMatchObject({ ok: true, value: { items: [] } });
		if (!first.ok) throw new Error('First page failed');
		const cursor = first.value.nextCursor;
		expect(cursor).toMatch(/^v1\.identity-v1\./u);
		expect(calls).toBe(1);
		const changedScope = await handleInspection({ ...input, filter: 'created', cursor }, deps);
		expect(changedScope).toMatchObject({ ok: false, error: { code: 'validation_error' } });
		expect(calls).toBe(1);

		const secondSource = rows<ModelRecord>({ onQuery: (options) => { receivedCursor = options?.cursor; } });
		const second = await handleInspection({ ...input, cursor }, dependencies({ intents: secondSource }));
		expect(second).toMatchObject({ ok: true, value: { items: [] } });
		expect(receivedCursor).toBe('host-page-2');
	});

	it('queries payments through the profile/environment/state index and projects encrypted data without leaks', async () => {
		const encrypted = await encryptSnapshot();
		const data = admittedIntent(encrypted);
		let queryOptions: Parameters<VersionedCollection<ModelRecord>['query']>[0];
		const intents = rows<ModelRecord>({
			items: [{ id: INTENT_ID, data }],
			onQuery: (options) => { queryOptions = options; },
		});
		const result = await handleInspection({ view: 'payments', filter: 'pending' }, dependencies({ intents }));
		expect(result).toMatchObject({ ok: true });
		if (!result.ok) throw new Error('Payment inspection failed');
		expect(queryOptions).toMatchObject({
			where: { merchantId: PROFILE_ID, environment: { in: ['test', 'live'] }, state: 'pending' },
			orderBy: { createdAt: 'desc' },
			limit: 25,
		});
		expect(result.value.items).toHaveLength(1);
		expect(result.value.items[0]).toMatchObject({
			paymentId: INTENT_ID,
			intentId: INTENT_ID,
			attemptId: ATTEMPT_ID,
			merchantProfileId: PROFILE_ID,
			environment: 'test',
			formId: 'membership_dues',
			formRevision: '3',
			expectedAmount: { currency: 'NGN', value: '2500.00' },
			moneyState: 'unpaid',
			attemptState: 'pending',
		});
		const serialized = JSON.stringify(result.value);
		for (const secret of ['payer@example.test', 'private-order-reference', 'private custom field', 'private metadata', 'provider-reference-private']) {
			expect(serialized).not.toContain(secret);
		}
	});

	it('returns payment detail by one exact opaque intent ID and correlates provider references', async () => {
		const encrypted = await encryptSnapshot();
		const data = { ...admittedIntent(encrypted, 'requires_action'), verificationState: 'unverified' };
		const intents = rows<ModelRecord>({ items: [{ id: INTENT_ID, data }] });
		const result = await handleInspection({ view: 'payment-detail', id: INTENT_ID }, dependencies({ intents }));
		expect(result).toMatchObject({ ok: true });
		if (!result.ok) throw new Error('Payment detail failed');
		expect(result.value.items).toHaveLength(1);
		const detail = result.value.items[0]!;
		expect(detail).toMatchObject({ maskedEmail: 'p••••@••••', verificationState: 'unverified' });
		expect(detail.providerReferenceCorrelationId).toMatch(/^rf_[a-f0-9]{64}$/u);
		expect(JSON.stringify(detail)).not.toContain('payer@example.test');
		expect(JSON.stringify(detail)).not.toContain('provider-reference-private');
		expect(JSON.stringify(detail)).not.toContain('private custom field');
	});

	it('decrypts customer email only for masking and re-correlates the provider customer ID', async () => {
		const scope = ['frontend_site_1', 'member', 'member_9', PROFILE_ID, 'test'];
		const customerId = deterministicRecordId('customers', await hmacIndex(['paystack-customer-map-v1', ...scope], identityKey));
		const subjectId = `psk:v1:subjects:${await hmacIndex(['paystack-customer-subject-v1', ...scope], identityKey)}`;
		const encryptedEmail = await encryptValue('customer@example.test', fieldKey, {
			pluginId: PLUGIN_ID, collection: 'customers', recordId: customerId, schemaVersion: 1, purpose: 'payer_email',
		});
		let queryOptions: Parameters<VersionedCollection<ModelRecord>['query']>[0];
		const customer: ModelRecord = {
			modelVersion: 1,
			customerCorrelationId: customerId,
			subjectCorrelationId: subjectId,
			providerCustomerId: '123456789',
			profileId: PROFILE_ID,
			environment: 'test',
			mappingState: 'mapped',
			encryptedEmail,
			emailVerifiedAt: '2026-10-18T09:01:00.000Z',
			createdAt: '2026-10-18T09:01:00.000Z',
			updatedAt: '2026-10-18T09:01:00.000Z',
		};
		const result = await handleInspection({ view: 'customers', filter: 'mapped' }, dependencies({
			customers: rows<ModelRecord>({ items: [{ id: customerId, data: customer }], onQuery: (options) => { queryOptions = options; } }),
		}));
		expect(result).toMatchObject({ ok: true });
		if (!result.ok) throw new Error('Customer inspection failed');
		expect(queryOptions).toMatchObject({ where: { profileId: PROFILE_ID, mappingState: 'mapped' }, orderBy: { createdAt: 'desc' } });
		expect(result.value.items[0]).toMatchObject({
			customerCorrelationId: customerId,
			subjectCorrelationId: subjectId,
			merchantProfileId: PROFILE_ID,
			maskedEmail: 'c••••@••••',
		});
		expect(result.value.items[0]?.providerCustomerCorrelationId).not.toBe('pc_123456789');
		const serialized = JSON.stringify(result.value);
		expect(serialized).not.toContain('customer@example.test');
		expect(serialized).not.toContain('123456789');
	});

	it('projects only signed inbox correlation data for webhook event inspection', async () => {
		const semanticKey = 'd'.repeat(64);
		let queryOptions: Parameters<VersionedCollection<ModelRecord>['query']>[0];
		const inboxRecord: ModelRecord = {
			modelVersion: 1,
			semanticKey,
			payloadDigest: 'e'.repeat(64),
			profileId: PROFILE_ID,
			environment: 'test',
			credentialVersion: 1,
			eventType: 'charge.success',
			reference: 'provider-reference-private',
			providerResourceId: '987654321',
			intentId: null,
			attemptId: null,
			state: 'accepted',
			dueAt: NOW,
			leaseEpoch: 0,
			acceptedAt: '2026-10-18T09:30:00.000Z',
			purgeAt: NOW + 1_000_000,
		};
		const result = await handleInspection({ view: 'webhook-events', filter: 'accepted' }, dependencies({
			inbox: rows<ModelRecord>({ items: [{ id: deterministicRecordId('inbox', semanticKey), data: inboxRecord }], onQuery: (options) => { queryOptions = options; } }),
		}));
		expect(result).toMatchObject({ ok: true });
		if (!result.ok) throw new Error('Webhook event inspection failed');
		expect(queryOptions).toMatchObject({ where: { profileId: PROFILE_ID, state: 'accepted' }, orderBy: { acceptedAt: 'desc' } });
		expect(result.value.items[0]).toMatchObject({
			eventId: `psk:v1:inbox:${semanticKey}`,
			merchantProfileId: PROFILE_ID,
			environment: 'test',
			authenticityState: 'verified',
			processingState: 'pending',
		});
		const serialized = JSON.stringify(result.value);
		expect(serialized).not.toContain('provider-reference-private');
		expect(serialized).not.toContain('987654321');
	});

	it('rejects unknown filters and extra fields before reading configuration', async () => {
		let settingsReads = 0;
		const deps = dependencies();
		const settings = {
			...deps.settings,
			getVersioned: async <T>() => { settingsReads += 1; return { value: JSON.stringify(configuration()) as T, revision: 'r1' }; },
		};
		expect(await handleInspection({ view: 'payments', filter: 'payer@example.test' }, { ...deps, settings }))
			.toMatchObject({ ok: false, error: { code: 'validation_error' } });
		expect(await handleInspection({ view: 'payments', unexpected: true }, { ...deps, settings }))
			.toMatchObject({ ok: false, error: { code: 'validation_error' } });
		expect(settingsReads).toBe(0);
	});
});
