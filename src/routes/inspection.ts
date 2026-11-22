import type { PluginContext, SandboxedRouteContext } from 'emdash/plugin';
import {
	PAYMENT_CONFIGURATION_SETTING,
	parsePaymentConfigurationSetting,
	type StoredPaymentConfiguration,
	type SettingsPort,
} from '../domain/configuration.js';
import { projectAdminCustomer, projectAdminPayment, projectAdminPaymentDetail, projectAdminWebhookEvent, type AdminProjection } from '../domain/admin-projection.js';
import { meterCollection, meterSettings, StageBudget } from '../security/limits.js';
import {
	readFieldEncryptionKeys,
	createIndexHmacKey,
	decodeBase64Url,
	decryptValue,
	hmacIndex,
	type DataEncryptionKey,
	type IndexHmacKey,
} from '../security/encryption.js';
import { hasExactKeys } from '../security/json.js';
import type { AdmittedPaymentSnapshot } from '../storage/admission.js';
import { isAdmissionIntentRecord } from '../storage/admission.js';
import { isWebhookInboxRecord, type WebhookInboxRecord } from '../storage/inbox.js';
import { isVerifiedPaymentResult } from '../domain/result.js';
import { verifyInspectionCursor, signInspectionCursor, type InspectionCursorContext, type InspectionCursorKeys, type InspectionSort, type InspectionView } from '../storage/cursors.js';
import { isPlainObject, deterministicRecordId, type ModelRecord, type VersionedCollection } from '../storage/schema.js';
import { isProviderIntentRecord, type ProviderAttemptRecord, type ProviderIntentRecord } from '../storage/provider-work.js';
import { domainError, domainOk, type DomainResult } from './response.js';

const INTENT_ID = /^psk:v1:intents:[a-f0-9]{64}$/u;
const SAFE_STATES = ['created', 'initializing', 'requires_action', 'pending', 'unknown', 'verified_paid', 'verified_failed', 'verified_canceled', 'review_required'] as const;
const WEBHOOK_STATES = ['accepted', 'processing', 'done', 'review'] as const;
const CUSTOMER_STATES = ['mapped', 'unmapped', 'error', 'unknown'] as const;

type InspectionRows = Pick<VersionedCollection<ModelRecord>, 'getVersioned' | 'query'>;

export interface InspectionResponse {
	readonly items: readonly AdminProjection[];
	readonly nextCursor?: string;
}

export interface InspectionDependencies {
	readonly pluginId: string;
	readonly siteUrl: string;
	readonly settings: SettingsPort;
	readonly intents: InspectionRows;
	readonly customers: InspectionRows;
	readonly inbox: InspectionRows;
	readonly now?: () => number;
	readonly crypto?: Crypto;
}

/** Private, bounded inspection. The EmDash route dispatcher authorizes session/token, RBAC, and CSRF first. */
export async function inspectionRoute(routeCtx: SandboxedRouteContext, ctx: PluginContext): Promise<unknown> {
	const budget = new StageBudget('admin', () => Date.now());
	const collection = (name: 'intents' | 'customers' | 'inbox'): InspectionRows =>
		meterCollection(ctx.storage[name] as unknown as VersionedCollection<ModelRecord>, budget);
	const settings = meterSettings(ctx.settings, budget);
	let result: DomainResult<InspectionResponse>;
	try {
		result = await handleInspection(routeCtx.input, {
			pluginId: ctx.plugin.id,
			siteUrl: ctx.site.url,
			settings,
			intents: collection('intents'),
			customers: collection('customers'),
			inbox: collection('inbox'),
		});
	} catch {
		result = domainError('storage_unavailable');
	}
	return result.ok ? domainOk(result.value) : domainError(result.error.code);
}

/** Domain implementation uses only exact reads or indexed, bounded collection queries. */
export async function handleInspection(input: unknown, dependencies: InspectionDependencies): Promise<DomainResult<InspectionResponse>> {
	const request = parseRequest(input);
	if (!request) return domainError('validation_error');
	const now = dependencies.now ?? Date.now;
	const nowMs = now();
	if (!Number.isSafeInteger(nowMs) || nowMs < 0) return domainError('storage_unavailable');
	const loaded = await loadConfiguration(dependencies.settings);
	if (loaded.kind === 'error') return domainError('storage_unavailable');
	if (!loaded.configuration?.activeProfile) return request.cursor ? domainError('storage_unavailable') : domainOk({ items: [] });
	const configuration = loaded.configuration;
	const profileId = configuration.activeProfile;
	if (typeof profileId !== 'string') return request.cursor ? domainError('storage_unavailable') : domainOk({ items: [] });
	const profile = configuration.profiles[profileId];
	if (!profile) return domainError('storage_unavailable');
	const identityKeys = makeIdentityKeys(configuration);
	const encryptionKeys = makeEncryptionKeys(configuration);
	if (!identityKeys || !encryptionKeys) return domainError('storage_unavailable');
	const siteBinding = normalizeSiteBinding(dependencies.siteUrl);
	if (!siteBinding) return domainError('storage_unavailable');
	if (request.view === 'payment-detail') {
		return detailById(request.id!, profileId, dependencies, identityKeys.active, encryptionKeys, nowMs);
	}
	const scope: InspectionCursorContext = {
		siteBinding,
		view: request.view,
		filter: request.filter,
		sort: request.sort,
		limit: request.limit,
	};
	let storageCursor: string | undefined;
	if (request.cursor) {
		storageCursor = await verifyInspectionCursor(request.cursor, scope, identityKeys, nowMs, dependencies.crypto ?? globalThis.crypto) ?? undefined;
		if (!storageCursor) return domainError('validation_error');
	}
	const order = request.sort.endsWith(':asc') ? 'asc' : 'desc';
	try {
		let page: { items: Array<{ id: string; data: ModelRecord }>; cursor?: string; hasMore: boolean };
		let items: AdminProjection[];
		if (request.view === 'customers') {
			const where: Record<string, unknown> = { profileId };
			if (request.filter) where.mappingState = request.filter;
			page = await dependencies.customers.query({
				where,
				orderBy: { createdAt: order }, limit: request.limit,
				...(storageCursor ? { cursor: storageCursor } : {}),
			});
			items = await projectCustomers(page.items, dependencies.pluginId, identityKeys.active, encryptionKeys, dependencies.crypto ?? globalThis.crypto);
		} else if (request.view === 'payments') {
			const where: Record<string, unknown> = { merchantId: profileId, environment: { in: ['test', 'live'] } };
			if (request.filter) where.state = request.filter;
			page = await dependencies.intents.query({
				where,
				orderBy: { createdAt: order }, limit: request.limit,
				...(storageCursor ? { cursor: storageCursor } : {}),
			});
			items = await projectPayments(page.items, profileId, dependencies.pluginId, identityKeys.active, encryptionKeys,
				false, dependencies.crypto ?? globalThis.crypto);
		} else {
			const where: Record<string, unknown> = { profileId };
			if (request.filter) where.state = request.filter;
			page = await dependencies.inbox.query({
				where,
				orderBy: { acceptedAt: order }, limit: request.limit,
				...(storageCursor ? { cursor: storageCursor } : {}),
			});
			items = page.items.flatMap((item) => {
				if (!isWebhookInboxRecord(item.data)) return [];
				const record = item.data;
				const eventId = deterministicRecordId('inbox', record.semanticKey);
				return [projectAdminWebhookEvent({
					eventId,
					paymentId: record.intentId ?? undefined,
					attemptId: record.attemptId ?? undefined,
					providerEventCorrelationId: `pe_${record.semanticKey}`,
					merchantProfileId: record.profileId,
					environment: record.environment,
					authenticityState: 'verified',
					processingState: webhookProcessingState(record.state),
					receivedAt: record.acceptedAt,
					failureCode: record.state === 'review' ? 'review_required' : undefined,
				})].filter(isProjection);
			});
		}
		if (page.hasMore && !page.cursor) return domainError('storage_unavailable');
		const nextCursor = page.hasMore
			? await signInspectionCursor(page.cursor!, scope, identityKeys, nowMs, dependencies.crypto ?? globalThis.crypto)
			: null;
		if (page.hasMore && !nextCursor) return domainError('storage_unavailable');
		return domainOk({ items: Object.freeze(items), ...(nextCursor ? { nextCursor } : {}) });
	} catch {
		return domainError('storage_unavailable');
	}
}

async function detailById(
	intentId: string,
	profileId: string,
	dependencies: InspectionDependencies,
	identityKey: IndexHmacKey,
	encryptionKeys: ReadonlyMap<string, DataEncryptionKey>,
	nowMs: number,
): Promise<DomainResult<InspectionResponse>> {
	if (!INTENT_ID.test(intentId)) return domainError('validation_error');
	try {
		const found = await dependencies.intents.getVersioned(intentId);
		if (!found || !isAdmissionIntentRecord(found.value) || !isProviderIntentRecord(found.value) ||
			found.value.identityHmac !== intentId || found.value.merchantId !== profileId || found.value.merchantProfile !== profileId) {
			return domainOk({ items: [] });
		}
		const items = await projectPayments([{ id: intentId, data: found.value }], profileId, dependencies.pluginId, identityKey,
			encryptionKeys, true, dependencies.crypto ?? globalThis.crypto, nowMs);
		return domainOk({ items: Object.freeze(items) });
	} catch {
		return domainError('storage_unavailable');
	}
}

async function projectCustomers(
	items: readonly { readonly id: string; readonly data: ModelRecord }[],
	pluginId: string,
	identityKey: IndexHmacKey,
	keys: ReadonlyMap<string, DataEncryptionKey>,
	cryptoProvider: Crypto,
): Promise<AdminProjection[]> {
	const projected: AdminProjection[] = [];
	for (const item of items) {
		if (!isPlainObject(item.data)) continue;
		let email: unknown;
		if (isEncryptedEnvelope(item.data.encryptedEmail)) {
			try {
				email = await decryptValue<string>(item.data.encryptedEmail, keys, {
					pluginId, collection: 'customers', recordId: item.id, schemaVersion: 1, purpose: 'payer_email',
				}, cryptoProvider);
			} catch {
				// Keep the record inspectable; the projection omits an unavailable email mask.
			}
		}
		let providerCustomerCorrelationId: string | undefined;
		if (typeof item.data.providerCustomerId === 'string') {
			try {
				providerCustomerCorrelationId = `pc_${await hmacIndex(['paystack-admin-provider-customer-v1', item.data.providerCustomerId], identityKey, cryptoProvider)}`;
			} catch {
				// A missing correlation ID is safer than exposing the provider's numeric identifier.
			}
		}
		const view = projectAdminCustomer({
			customerCorrelationId: item.data.customerCorrelationId ?? item.id,
			subjectCorrelationId: item.data.subjectCorrelationId,
			providerCustomerCorrelationId,
			merchantProfileId: item.data.profileId,
			environment: item.data.environment,
			mappingState: item.data.mappingState,
			createdAt: item.data.createdAt,
			updatedAt: item.data.updatedAt,
			email,
		});
		if (view) projected.push(view);
	}
	return projected;
}

async function projectPayments(
	items: readonly { readonly id: string; readonly data: ModelRecord }[],
	profileId: string,
	pluginId: string,
	identityKey: IndexHmacKey,
	encryptionKeys: ReadonlyMap<string, DataEncryptionKey>,
	detail: boolean,
	cryptoProvider: Crypto,
	_nowMs?: number,
): Promise<AdminProjection[]> {
	const output: AdminProjection[] = [];
	for (const item of items) {
		if (!isAdmissionIntentRecord(item.data) || !isProviderIntentRecord(item.data) ||
			item.data.identityHmac !== item.id || item.data.merchantId !== profileId || item.data.merchantProfile !== profileId) continue;
		const intent = item.data as unknown as ProviderIntentRecord & Record<string, unknown>;
		const attempt = intent.attempts.find((candidate) => candidate.id === intent.currentAttemptId) as ProviderAttemptRecord | undefined;
		if (!attempt) continue;
		const paidState = isConsistentPaidReceipt(intent, item.id);
		const snapshot = await readSnapshot(pluginId, item.id, intent.protectedSnapshot, encryptionKeys, cryptoProvider);
		const customerCorrelationId = snapshot ? await deriveCustomerCorrelation(snapshot, profileId, intent.environment, identityKey, cryptoProvider) : undefined;
		const expectedAmount = snapshot?.amount;
		const base: Record<string, unknown> = {
			paymentId: item.id,
			intentId: item.id,
			attemptId: attempt.id,
			customerCorrelationId,
			merchantProfileId: profileId,
			environment: intent.environment,
			formId: intent.formId,
			formRevision: intent.formRevision,
			expectedAmount: expectedAmount ? { currency: expectedAmount.currency, value: expectedAmount.value } : undefined,
			moneyState: paymentMoneyState(intent.state, paidState),
			attemptState: attempt.state,
			deliveryState: intent.deliveryState,
			createdAt: intent.createdAt,
			updatedAt: intent.updatedAt,
			verifiedAt: intent.verifiedAt,
		};
		if (!detail) {
			const view = projectAdminPayment(base);
			if (view) output.push(view);
			continue;
		}
		const attempts = Array.isArray(intent.attempts) ? intent.attempts : [];
		const result = isVerifiedPaymentResult(intent.resultEvent) && paidState ? intent.resultEvent : null;
		const resourceId = result ? result.providerResourceId : typeof attempt.providerResourceId === 'string' ? attempt.providerResourceId : undefined;
		const reference = result ? result.providerReference : typeof attempt.providerReference === 'string' ? attempt.providerReference : undefined;
		const providerResourceCorrelationId = resourceId
			? `pr_${await hmacIndex(['paystack-admin-provider-resource-v1', resourceId], identityKey, cryptoProvider)}` : undefined;
		const providerReferenceCorrelationId = reference
			? `rf_${await hmacIndex(['paystack-admin-provider-reference-v1', reference], identityKey, cryptoProvider)}` : undefined;
		const receiptAmount = paidState && isPlainObject(intent.receipt) ? intent.receipt.amount : undefined;
		const email = snapshot && isPlainObject(snapshot.fields) ? snapshot.fields.payer_email : undefined;
		const view = projectAdminPaymentDetail({
			...base,
			providerResourceCorrelationId,
			providerReferenceCorrelationId,
			resultEventId: result && intent.resultEventId === result.eventId ? result.eventId : undefined,
			providerAmount: receiptAmount,
			verificationState: intent.verificationState,
			email,
			history: attempts.map((candidate) => ({
				attemptId: candidate.id,
				state: candidate.state,
				occurredAt: candidate.updatedAt,
				failureCode: (candidate as unknown as Record<string, unknown>).failureCode,
			})),
		});
		if (view) output.push(view);
	}
	return output;
}

async function readSnapshot(
	pluginId: string,
	intentId: string,
	protectedSnapshot: unknown,
	keys: ReadonlyMap<string, DataEncryptionKey>,
	cryptoProvider: Crypto,
): Promise<AdmittedPaymentSnapshot | null> {
	if (!isEncryptedEnvelope(protectedSnapshot)) return null;
	try {
		const value = await decryptValue<unknown>(protectedSnapshot, keys, {
			pluginId, collection: 'intents', recordId: intentId, schemaVersion: 1, purpose: 'custom_fields',
		}, cryptoProvider);
		return isPlainObject(value) && isPlainObject(value.amount) && isPlainObject(value.subject) && isPlainObject(value.fields)
			? value as unknown as AdmittedPaymentSnapshot : null;
	} catch {
		return null;
	}
}

async function deriveCustomerCorrelation(
	snapshot: AdmittedPaymentSnapshot,
	profileId: string,
	environment: 'test' | 'live',
	key: IndexHmacKey,
	cryptoProvider: Crypto,
): Promise<string | undefined> {
	if (!snapshot.siteId || !snapshot.subject || typeof snapshot.subject.kind !== 'string' || typeof snapshot.subject.id !== 'string') return undefined;
	try {
		const digest = await hmacIndex([
			'paystack-customer-map-v1', snapshot.siteId, snapshot.subject.kind, snapshot.subject.id, profileId, environment,
		], key, cryptoProvider);
		return deterministicRecordId('customers', digest);
	} catch {
		return undefined;
	}
}

function parseRequest(value: unknown): {
	readonly view: InspectionView;
	readonly id?: string;
	readonly cursor?: string;
	readonly limit: number;
	readonly sort: InspectionSort;
	readonly filter: string | null;
} | null {
	if (!isPlainObject(value) || typeof value.view !== 'string') return null;
	if (value.view === 'payment-detail') {
		if (!hasExactKeys(value, ['view', 'id']) || typeof value.id !== 'string' || !INTENT_ID.test(value.id)) return null;
		return { view: value.view, id: value.id, limit: 1, sort: 'createdAt:desc', filter: null };
	}
	if (value.view !== 'customers' && value.view !== 'payments' && value.view !== 'webhook-events' ||
		!hasExactKeys(value, ['view'], ['cursor', 'limit', 'sort', 'filter'])) return null;
	if (value.cursor !== undefined && (typeof value.cursor !== 'string' || value.cursor.length > 4_096) ||
		value.limit !== undefined && (!Number.isSafeInteger(value.limit) || typeof value.limit !== 'number' || value.limit < 1 || value.limit > 50) ||
		value.sort !== undefined && value.sort !== 'createdAt:asc' && value.sort !== 'createdAt:desc' ||
		value.filter !== undefined && (typeof value.filter !== 'string' || value.filter.length > 120)) return null;
	const filter = typeof value.filter === 'string' ? value.filter : null;
	if (!isAllowedFilter(value.view, filter)) return null;
	return {
		view: value.view,
		...(typeof value.cursor === 'string' ? { cursor: value.cursor } : {}),
		limit: typeof value.limit === 'number' ? value.limit : 25,
		sort: value.sort === 'createdAt:asc' ? 'createdAt:asc' : 'createdAt:desc',
		filter,
	};
}

function isAllowedFilter(view: InspectionView, filter: string | null): boolean {
	if (filter === null) return true;
	if (view === 'customers') return (CUSTOMER_STATES as readonly string[]).includes(filter);
	if (view === 'payments') return (SAFE_STATES as readonly string[]).includes(filter);
	if (view === 'webhook-events') return (WEBHOOK_STATES as readonly string[]).includes(filter);
	return false;
}

async function loadConfiguration(settings: SettingsPort): Promise<
	{ readonly kind: 'ok'; readonly configuration: StoredPaymentConfiguration | null } | { readonly kind: 'error' }
> {
	try {
		const stored = await settings.getVersioned<unknown>(PAYMENT_CONFIGURATION_SETTING);
		if (!stored) return { kind: 'ok', configuration: null };
		const parsed = parsePaymentConfigurationSetting(stored.value);
		return parsed ? { kind: 'ok', configuration: parsed } : { kind: 'error' };
	} catch {
		return { kind: 'error' };
	}
}

function makeIdentityKeys(configuration: StoredPaymentConfiguration): InspectionCursorKeys & { readonly active: IndexHmacKey } | null {
	try {
		const keys = configuration.identityHmacKeyRing.keys.map((entry) => createIndexHmacKey(entry.keyId, decodeBase64Url(entry.material)));
		const active = keys.find((entry) => entry.keyId === configuration.identityHmacKeyRing.activeKeyId);
		return active ? { activeKeyId: active.keyId, keys: Object.freeze(keys), active } : null;
	} catch {
		return null;
	}
}

function makeEncryptionKeys(configuration: StoredPaymentConfiguration): ReadonlyMap<string, DataEncryptionKey> | null {
	const keys = readFieldEncryptionKeys(configuration.fieldEncryptionKeyRing.keys);
	return keys?.has(configuration.fieldEncryptionKeyRing.activeKeyId) ? keys : null;
}

function normalizeSiteBinding(value: string): string | null {
	if (typeof value !== 'string' || value.length < 1 || value.length > 2_048) return null;
	try {
		const url = new URL(value);
		if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) return null;
		return url.origin;
	} catch {
		return null;
	}
}

function isEncryptedEnvelope(value: unknown): value is { version: 1; algorithm: 'A256GCM'; keyId: string; iv: string; ciphertext: string } {
	return isPlainObject(value) && value.version === 1 && value.algorithm === 'A256GCM' && typeof value.keyId === 'string' &&
		typeof value.iv === 'string' && typeof value.ciphertext === 'string';
}


function paymentMoneyState(state: unknown, paidState: boolean): string {
	if (state === 'verified_paid') return paidState ? 'verified_paid' : 'unknown';
	if (state === 'review_required') return 'review_required';
	if (state === 'created' || state === 'initializing' || state === 'requires_action' || state === 'pending' ||
		state === 'verified_failed' || state === 'verified_canceled') return 'unpaid';
	return 'unknown';
}

function isConsistentPaidReceipt(intent: Record<string, unknown>, intentId: string): boolean {
	const result = intent.resultEvent;
	const receipt = intent.receipt;
	if (intent.state !== 'verified_paid' || !isVerifiedPaymentResult(result) || !isPlainObject(receipt) ||
		result.intentId !== intentId || result.paymentId !== intentId || result.eventId !== intent.resultEventId ||
		result.merchantProfile !== intent.merchantProfile || result.environment !== intent.environment ||
		result.formId !== intent.formId || result.formRevision !== intent.formRevision ||
		receipt.provider !== 'paystack' || receipt.status !== 'success' ||
		receipt.providerReference !== result.providerReference || receipt.providerResourceId !== result.providerResourceId ||
		receipt.domain !== result.environment || receipt.verifiedAt !== result.verifiedAt || !isPlainObject(receipt.amount) ||
		receipt.amount.currency !== result.amount.currency || receipt.amount.value !== result.amount.value) return false;
	const attempt = Array.isArray(intent.attempts) ? intent.attempts.find((candidate) => isPlainObject(candidate) && candidate.id === result.attemptId) : undefined;
	return Boolean(attempt && isPlainObject(attempt) && attempt.providerReference === result.providerReference &&
		(attempt.providerResourceId === undefined || attempt.providerResourceId === null || attempt.providerResourceId === result.providerResourceId));
}

function webhookProcessingState(state: WebhookInboxRecord['state']): string {
	switch (state) {
		case 'accepted': return 'pending';
		case 'processing': return 'processing';
		case 'done': return 'completed';
		case 'review': return 'failed';
	}
}

function isProjection(value: AdminProjection | null): value is AdminProjection {
	return value !== null;
}
