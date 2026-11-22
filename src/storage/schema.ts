export const STORAGE_SCHEMA_VERSION = 1 as const;
export const MAX_AGGREGATE_BYTES = 256 * 1024;
export const MAX_ATTEMPTS_PER_INTENT = 10;
export const MAX_QUERY_LIMIT = 50;
export const MAX_WORKER_SELECTION = 25;

/** Query indexes are deliberately limited to the scalar fields used by the approved data model. */
export const STORAGE_SCHEMA = {
	profiles: {
		indexes: [['merchantId', 'environment'], 'operationalState', 'credentialVersion'],
		uniqueIndexes: [['merchantId', 'environment', 'profileId']],
	},
	forms: {
		indexes: [['state', 'updatedAt'], 'updatedAt'],
	},
	intents: {
		indexes: [
			['siteId', 'createdAt'],
			['merchantId', 'environment', 'createdAt'],
				['merchantId', 'environment', 'state', 'createdAt'],
			['state', 'nextRunAt'],
			['deliveryState', 'verifiedAt'],
			['consumerId', 'deliveryState', 'verifiedAt'],
			['siteId', 'consumerId', 'deliveryState', 'verifiedAt'],
			'resultEventId',
			['formId', 'createdAt'],
			'purgeAt',
		],
	},
	request_keys: {
		indexes: [['intentId', 'createdAt']],
		uniqueIndexes: ['scopeKey'],
	},
	inbox: {
		indexes: [
			['state', 'dueAt'],
			['profileId', 'acceptedAt'],
			['profileId', 'state', 'acceptedAt'],
			['intentId', 'acceptedAt'],
			'purgeAt',
		],
	},
	customers: {
		indexes: [['profileId', 'updatedAt'], ['profileId', 'createdAt'], ['profileId', 'mappingState', 'createdAt'], 'purgeAt'],
	},
	nonces: {
		indexes: ['expiresAt'],
	},
	budgets: {
		indexes: ['expiresAt'],
	},
} as const satisfies Record<
	string,
	{ indexes: readonly (string | readonly string[])[]; uniqueIndexes?: readonly (string | readonly string[])[] }
>;

export type CollectionName = keyof typeof STORAGE_SCHEMA;
export type ModelRecord = {
	readonly modelVersion: number;
	readonly [field: string]: unknown;
};

/** Structural subset of EmDash 1.3 StorageCollection, verified against its exported PluginContext API. */
export interface VersionedCollection<T> {
	getVersioned(id: string): Promise<{ value: T; revision: string } | null>;
	compareAndSet(
		id: string,
		expectedRevision: string | null,
		data: T,
	): Promise<{ applied: true; revision: string } | { applied: false }>;
	compareAndDelete(id: string, expectedRevision: string): Promise<{ applied: boolean }>;
	query(options?: {
		where?: Record<string, unknown>;
		orderBy?: Record<string, 'asc' | 'desc'>;
		limit?: number;
		cursor?: string;
	}): Promise<{ items: Array<{ id: string; data: T }>; cursor?: string; hasMore: boolean }>;
}

export interface BoundedQueryOptions {
	readonly where?: Record<string, unknown>;
	readonly orderBy?: Record<string, 'asc' | 'desc'>;
	readonly limit?: number;
	readonly cursor?: string;
}

export class StorageInvariantError extends Error {
	readonly code: string;

	constructor(code: string) {
		super(code);
		this.name = 'StorageInvariantError';
		this.code = code;
	}
}

export function assertSupportedRecord<T extends ModelRecord>(value: unknown): asserts value is T {
	if (!isPlainObject(value)) throw new StorageInvariantError('INVALID_RECORD');
	const version = value.modelVersion;
	if (!Number.isSafeInteger(version) || typeof version !== 'number' || version < 1) {
		throw new StorageInvariantError('INVALID_SCHEMA_VERSION');
	}
	if (version > STORAGE_SCHEMA_VERSION) {
		throw new StorageInvariantError('UNSUPPORTED_SCHEMA_VERSION');
	}
	if (version !== STORAGE_SCHEMA_VERSION) {
		throw new StorageInvariantError('MIGRATION_REQUIRED');
	}
	assertBoundedRecord(value);
}

export function assertBoundedRecord(value: unknown): asserts value is ModelRecord {
	if (!isPlainObject(value)) throw new StorageInvariantError('INVALID_RECORD');
	let encoded: string;
	try {
		encoded = JSON.stringify(value);
	} catch {
		throw new StorageInvariantError('INVALID_RECORD');
	}
	if (typeof encoded !== 'string' || new TextEncoder().encode(encoded).byteLength > MAX_AGGREGATE_BYTES) {
		throw new StorageInvariantError('AGGREGATE_TOO_LARGE');
	}
	if ('attempts' in value) {
		if (!Array.isArray(value.attempts)) throw new StorageInvariantError('INVALID_ATTEMPTS');
		if (value.attempts.length > MAX_ATTEMPTS_PER_INTENT) {
			throw new StorageInvariantError('ATTEMPT_LIMIT_EXCEEDED');
		}
	}
}

export function assertQueryLimit(limit: number, max = MAX_QUERY_LIMIT): number {
	if (!Number.isSafeInteger(limit) || limit < 1 || limit > max || max > MAX_QUERY_LIMIT) {
		throw new StorageInvariantError('QUERY_LIMIT_EXCEEDED');
	}
	return limit;
}

export async function queryBounded<T>(
	collection: VersionedCollection<T>,
	options: BoundedQueryOptions = {},
	max = MAX_QUERY_LIMIT,
): Promise<{ items: Array<{ id: string; data: T }>; cursor?: string; hasMore: boolean }> {
	const limit = assertQueryLimit(options.limit ?? max, max);
	return collection.query({ ...options, limit });
}

export function assertWorkerSelection(limit: number): number {
	return assertQueryLimit(limit, MAX_WORKER_SELECTION);
}

/** IDs must already be opaque cryptographic digests; caller data is never used as a storage key. */
export function deterministicRecordId(collection: CollectionName, digest: string): string {
	if (!/^[a-f0-9]{64}$/.test(digest)) throw new StorageInvariantError('INVALID_OPAQUE_KEY');
	return `psk:v1:${collection}:${digest}`;
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
	if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
	const prototype = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
}
