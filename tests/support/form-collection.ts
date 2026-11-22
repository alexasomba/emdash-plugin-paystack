import type { StoredFormRecord } from '../../src/routes/forms.js';
import type { VersionedCollection } from '../../src/storage/schema.js';

interface StoredRow<T> {
	readonly revision: string;
	readonly value: T;
}

export class InMemoryFormCollection implements VersionedCollection<StoredFormRecord> {
	private readonly records = new Map<string, StoredRow<StoredFormRecord>>();
	private nextRevisionNumber = 1;
	private conflict: ((current: StoredFormRecord) => StoredFormRecord) | undefined;
	private nextCasError: Error | undefined;
	compareAndSetCalls = 0;

	seed(id: string, value: StoredFormRecord, revision = 'host-cas-1'): void {
		this.records.set(id, { revision, value: structuredClone(value) });
	}

	conflictOnce(update: (current: StoredFormRecord) => StoredFormRecord): void {
		this.conflict = update;
	}

	rejectNextCompareAndSet(error = new Error('fixture CAS rejected')): void {
		this.nextCasError = error;
	}

	async getVersioned(id: string): Promise<{ value: StoredFormRecord; revision: string } | null> {
		const row = this.records.get(id);
		return row ? { value: structuredClone(row.value), revision: row.revision } : null;
	}

	async compareAndSet(
		id: string,
		expectedRevision: string | null,
		data: StoredFormRecord,
	): Promise<{ applied: true; revision: string } | { applied: false }> {
		this.compareAndSetCalls += 1;
		const error = this.nextCasError;
		this.nextCasError = undefined;
		if (error) throw error;
		const current = this.records.get(id);
		if (this.conflict && current) {
			const update = this.conflict;
			this.conflict = undefined;
			this.records.set(id, { revision: this.newStorageRevision(), value: structuredClone(update(current.value)) });
			return { applied: false };
		}
		if ((current?.revision ?? null) !== expectedRevision) return { applied: false };
		const revision = this.newStorageRevision();
		this.records.set(id, { revision, value: structuredClone(data) });
		return { applied: true, revision };
	}

	async compareAndDelete(id: string, expectedRevision: string): Promise<{ applied: boolean }> {
		const current = this.records.get(id);
		if (!current || current.revision !== expectedRevision) return { applied: false };
		this.records.delete(id);
		return { applied: true };
	}

	async query(options: {
		where?: Record<string, unknown>;
		orderBy?: Record<string, 'asc' | 'desc'>;
		limit?: number;
		cursor?: string;
	} = {}): Promise<{ items: Array<{ id: string; data: StoredFormRecord }>; cursor?: string; hasMore: boolean }> {
		const ordered = [...this.records.entries()].sort((left, right) => {
			const sortDirection = options.orderBy?.updatedAt === 'asc' ? 1 : -1;
			return left[1].value.updatedAt.localeCompare(right[1].value.updatedAt) * sortDirection || left[0].localeCompare(right[0]);
		});
		const offset = options.cursor === undefined ? 0 : Number(options.cursor);
		if (!Number.isSafeInteger(offset) || offset < 0) throw new Error('Invalid fixture cursor');
		const limit = options.limit ?? 50;
		const page = ordered.slice(offset, offset + limit);
		const nextOffset = offset + page.length;
		return {
			items: page.map(([id, row]) => ({ id, data: structuredClone(row.value) })),
			...(nextOffset < ordered.length ? { cursor: String(nextOffset) } : {}),
			hasMore: nextOffset < ordered.length,
		};
	}

	inspect(id: string): { readonly value: StoredFormRecord; readonly storageRevision: string } | null {
		const row = this.records.get(id);
		return row ? { value: structuredClone(row.value), storageRevision: row.revision } : null;
	}

	private newStorageRevision(): string {
		return `host-cas-${this.nextRevisionNumber++}`;
	}
}
