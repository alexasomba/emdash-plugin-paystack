import { describe, expect, it } from 'vite-plus/test';
import {
	VersionedRepository,
	type RepositoryWrite,
} from '../../src/storage/aggregates.js';
import {
	assertBoundedRecord,
	assertQueryLimit,
	assertSupportedRecord,
	assertWorkerSelection,
	deterministicRecordId,
	queryBounded,
	StorageInvariantError,
	STORAGE_SCHEMA,
	type ModelRecord,
	type VersionedCollection,
} from '../../src/storage/schema.js';
import { claimLease, LEASE_DURATION_MS, ownsLease, type LeaseRecord } from '../../src/storage/leases.js';

class MemoryCollection<T> implements VersionedCollection<T> {
	private readonly rows = new Map<string, { value: T; revision: number }>();
	queryCalls: number[] = [];
	failWrite = false;

	async getVersioned(id: string) {
		const row = this.rows.get(id);
		return row ? { value: structuredClone(row.value), revision: String(row.revision) } : null;
	}

	async compareAndSet(id: string, expectedRevision: string | null, data: T) {
		const row = this.rows.get(id);
		const revision = row ? String(row.revision) : null;
		if (revision !== expectedRevision) return { applied: false as const };
		if (this.failWrite) throw new Error('unknown transport result');
		const next = (row?.revision ?? 0) + 1;
		this.rows.set(id, { value: structuredClone(data), revision: next });
		return { applied: true as const, revision: String(next) };
	}

	async compareAndDelete(id: string, expectedRevision: string) {
		const row = this.rows.get(id);
		if (!row || String(row.revision) !== expectedRevision) return { applied: false };
		this.rows.delete(id);
		return { applied: true };
	}

	async query(options: { limit?: number } = {}) {
		this.queryCalls.push(options.limit ?? 50);
		return { items: [], hasMore: false };
	}
}

type TestRecord = ModelRecord & { readonly attempts?: readonly unknown[]; readonly lease?: LeaseRecord['lease'] };

describe('storage foundation implementation', () => {
	it('declares bounded scalar/composite indexes and only accepts opaque deterministic keys', () => {
		expect(STORAGE_SCHEMA.intents.indexes).toContainEqual(['siteId', 'createdAt']);
		expect(STORAGE_SCHEMA.request_keys.uniqueIndexes).toContain('scopeKey');
		expect(deterministicRecordId('intents', 'a'.repeat(64))).toBe(`psk:v1:intents:${'a'.repeat(64)}`);
		expect(() => deterministicRecordId('intents', 'payer@example.test')).toThrow(StorageInvariantError);
	});

	it('fails closed on unknown versions, invalid attempt shape, oversize aggregates and unbounded selections', () => {
		expect(() => assertSupportedRecord({ modelVersion: 2 })).toThrow('UNSUPPORTED_SCHEMA_VERSION');
		expect(() => assertBoundedRecord({ modelVersion: 1, attempts: Array(11).fill({}) })).toThrow('ATTEMPT_LIMIT_EXCEEDED');
		expect(() => assertBoundedRecord({ modelVersion: 1, payload: 'x'.repeat(256 * 1024) })).toThrow('AGGREGATE_TOO_LARGE');
		expect(() => assertQueryLimit(51)).toThrow('QUERY_LIMIT_EXCEEDED');
		expect(() => assertWorkerSelection(26)).toThrow('QUERY_LIMIT_EXCEEDED');
	});

	it('uses one-record versioned CAS and does not retry an uncertain write', async () => {
		const collection = new MemoryCollection<TestRecord>();
		const repository = new VersionedRepository(collection);
		const created = await repository.create('opaque-record', { modelVersion: 1, state: 'pending' });
		expect(created.kind).toBe('written');
		if (created.kind !== 'written') return;
		expect((await repository.replace('opaque-record', 'stale', { modelVersion: 1, state: 'paid' })).kind).toBe('conflict');
		collection.failWrite = true;
		expect((await repository.replace('opaque-record', created.revision, { modelVersion: 1, state: 'paid' })).kind).toBe('unknown');
	});

	it('enforces list and worker query bounds before crossing the storage bridge', async () => {
		const collection = new MemoryCollection<TestRecord>();
		await queryBounded(collection, { limit: 50 });
		expect(collection.queryCalls).toEqual([50]);
		await expect(queryBounded(collection, { limit: 26 }, 25)).rejects.toThrow('QUERY_LIMIT_EXCEEDED');
		expect(collection.queryCalls).toEqual([50]);
	});

	it('claims a 45-second lease with a monotonic epoch and fences stale owners', async () => {
		const collection = new MemoryCollection<TestRecord>();
		const repository = new VersionedRepository(collection);
		const ownerA = 'worker_owner_0001';
		const ownerB = 'worker_owner_0002';
		await repository.create('intent', { modelVersion: 1, state: 'pending' });
		const first = await claimLease(repository as VersionedRepository<TestRecord & LeaseRecord>, 'intent', ownerA, 1_000);
		expect(first.kind).toBe('claimed');
		if (first.kind !== 'claimed') return;
		expect(first.lease.expiresAt).toBe(1_000 + LEASE_DURATION_MS);
		expect(ownsLease(first.value as LeaseRecord, first.lease, 2_000)).toBe(true);
		expect((await claimLease(repository as VersionedRepository<TestRecord & LeaseRecord>, 'intent', ownerB, 2_000)).kind).toBe('busy');
		const next = await claimLease(repository as VersionedRepository<TestRecord & LeaseRecord>, 'intent', ownerB, first.lease.expiresAt);
		expect(next.kind).toBe('claimed');
		if (next.kind === 'claimed') {
			expect(next.lease.epoch).toBe(2);
			expect(ownsLease(next.value as LeaseRecord, first.lease, first.lease.expiresAt)).toBe(false);
		}
	});
});
