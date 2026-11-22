import {
	assertSupportedRecord,
	deterministicRecordId,
	isPlainObject,
	MAX_AGGREGATE_BYTES,
	type ModelRecord,
	type VersionedCollection,
} from './schema.js';

export const WEBHOOK_INBOX_RETENTION_MS = 30 * 24 * 60 * 60_000;
export const MAX_WEBHOOK_INBOX_RECORD_BYTES = 4 * 1024;

export interface WebhookInboxRecord extends ModelRecord {
	readonly modelVersion: 1;
	readonly semanticKey: string;
	readonly payloadDigest: string;
	readonly profileId: string;
	readonly environment: 'test' | 'live';
	readonly credentialVersion: number;
	readonly eventType: string;
	readonly reference: string;
	readonly providerResourceId: string | null;
	readonly intentId: string | null;
	readonly attemptId: string | null;
	readonly state: 'accepted' | 'processing' | 'done' | 'review';
	readonly dueAt: number;
	readonly leaseEpoch: number;
	readonly acceptedAt: string;
	readonly purgeAt: number;
}

export type WebhookInboxAcceptance =
	| { readonly kind: 'durable'; readonly recordId: string; readonly record: WebhookInboxRecord; readonly duplicate: boolean }
	| { readonly kind: 'unavailable' };

/** Persist one bounded semantic event record; a raw provider body is never accepted by this API. */
export async function acceptWebhookInbox(
	collection: Pick<VersionedCollection<ModelRecord>, 'getVersioned' | 'compareAndSet'>,
	record: WebhookInboxRecord,
): Promise<WebhookInboxAcceptance> {
	if (!isWebhookInboxRecord(record)) return { kind: 'unavailable' };
	const recordId = deterministicRecordId('inbox', record.semanticKey);
	let current: { readonly value: ModelRecord; readonly revision: string } | null;
	try { current = await collection.getVersioned(recordId); } catch { return { kind: 'unavailable' }; }
	if (current) return confirmsSemanticEvent(current.value, record) ?
		{ kind: 'durable', recordId, record: current.value as WebhookInboxRecord, duplicate: true } : { kind: 'unavailable' };

	try {
		const written = await collection.compareAndSet(recordId, null, record);
		if (written.applied && typeof written.revision === 'string' && written.revision.length > 0) {
			return { kind: 'durable', recordId, record, duplicate: false };
		}
		// A conflicting or ambiguous write is acknowledged only after an exact-key read confirms it.
	} catch {
		// The host may have committed before its response was lost. Confirm with one read; never retry the write.
	}
	try {
		const after = await collection.getVersioned(recordId);
		if (after && confirmsSemanticEvent(after.value, record)) {
			return { kind: 'durable', recordId, record: after.value as WebhookInboxRecord, duplicate: true };
		}
	} catch {
		// A missing confirmation is retryable by the provider.
	}
	return { kind: 'unavailable' };
}

export function isWebhookInboxRecord(value: unknown): value is WebhookInboxRecord {
	if (!isPlainObject(value)) return false;
	const allowed = new Set([
		'modelVersion', 'semanticKey', 'payloadDigest', 'profileId', 'environment', 'credentialVersion',
		'eventType', 'reference', 'providerResourceId', 'intentId', 'attemptId', 'state', 'dueAt', 'leaseEpoch', 'acceptedAt', 'purgeAt',
	]);
	if (Object.keys(value).some((key) => !allowed.has(key)) ||
		!['modelVersion', 'semanticKey', 'payloadDigest', 'profileId', 'environment', 'credentialVersion',
			'eventType', 'reference', 'providerResourceId', 'intentId', 'attemptId', 'state', 'dueAt', 'leaseEpoch', 'acceptedAt', 'purgeAt']
			.every((key) => Object.hasOwn(value, key))) return false;
	try { assertSupportedRecord(value); } catch { return false; }
	if (value.modelVersion !== 1 || typeof value.semanticKey !== 'string' || !/^[a-f0-9]{64}$/u.test(value.semanticKey) ||
		typeof value.payloadDigest !== 'string' || !/^[a-f0-9]{64}$/u.test(value.payloadDigest) ||
		typeof value.profileId !== 'string' || !/^[A-Za-z0-9_-]{1,120}$/u.test(value.profileId) ||
		(value.environment !== 'test' && value.environment !== 'live') ||
		!Number.isSafeInteger(value.credentialVersion) || typeof value.credentialVersion !== 'number' || value.credentialVersion < 1 ||
		typeof value.eventType !== 'string' || !/^[a-z][a-z0-9_.-]{0,63}$/u.test(value.eventType) ||
		typeof value.reference !== 'string' || !/^[A-Za-z0-9.=\-]{1,100}$/u.test(value.reference) ||
		(value.providerResourceId !== null && (typeof value.providerResourceId !== 'string' || !/^[0-9]{1,24}$/u.test(value.providerResourceId))) ||
		value.intentId !== null && (typeof value.intentId !== 'string' || !/^psk:v1:intents:[a-f0-9]{64}$/u.test(value.intentId)) ||
		value.attemptId !== null && (typeof value.attemptId !== 'string' || !/^psk:v1:attempts:[a-f0-9]{64}$/u.test(value.attemptId)) ||
		(value.intentId === null) !== (value.attemptId === null) ||
		!['accepted', 'processing', 'done', 'review'].includes(String(value.state)) ||
		!Number.isSafeInteger(value.dueAt) || typeof value.dueAt !== 'number' || value.dueAt < 0 ||
		!Number.isSafeInteger(value.leaseEpoch) || typeof value.leaseEpoch !== 'number' || value.leaseEpoch < 0 ||
		typeof value.acceptedAt !== 'string' || !Number.isFinite(Date.parse(value.acceptedAt)) ||
		!Number.isSafeInteger(value.purgeAt) || typeof value.purgeAt !== 'number' || value.purgeAt < 0) return false;
	try {
		const bytes = new TextEncoder().encode(JSON.stringify(value)).byteLength;
		return bytes <= Math.min(MAX_WEBHOOK_INBOX_RECORD_BYTES, MAX_AGGREGATE_BYTES);
	} catch { return false; }
}

function confirmsSemanticEvent(existing: unknown, expected: WebhookInboxRecord): existing is WebhookInboxRecord {
	return isWebhookInboxRecord(existing) && existing.semanticKey === expected.semanticKey &&
		existing.profileId === expected.profileId && existing.environment === expected.environment &&
		existing.eventType === expected.eventType && existing.reference === expected.reference;
}
