import {
	assertBoundedRecord,
	assertSupportedRecord,
	type ModelRecord,
	type VersionedCollection,
} from './schema.js';

export type RepositoryWrite<T> =
	| { readonly kind: 'written'; readonly revision: string; readonly value: T }
	| { readonly kind: 'conflict' }
	| { readonly kind: 'unknown' };

/**
 * A single aggregate CAS with optional exact readback after an ambiguous bridge failure.
 * The write is never retried in this invocation; callers decide how to resume in a new one.
 */
export async function compareAndSetAggregate<T extends ModelRecord>(
	collection: VersionedCollection<T>,
	id: string,
	expectedRevision: string,
	value: T,
	confirms: (observed: T) => boolean = () => false,
): Promise<RepositoryWrite<T>> {
	if (!id || !expectedRevision) return { kind: 'conflict' };
	assertSupportedRecord(value);
	assertBoundedRecord(value);
	try {
		const result = await collection.compareAndSet(id, expectedRevision, value);
		return result.applied && result.revision
			? { kind: 'written', revision: result.revision, value }
			: result.applied ? { kind: 'unknown' } : { kind: 'conflict' };
	} catch {
		try {
			const observed = await collection.getVersioned(id);
			if (!observed?.revision) return { kind: 'unknown' };
			assertSupportedRecord<T>(observed.value);
			return confirms(observed.value)
				? { kind: 'written', revision: observed.revision, value: observed.value }
				: { kind: 'unknown' };
		} catch {
			return { kind: 'unknown' };
		}
	}
}

export class VersionedRepository<T extends ModelRecord> {
	constructor(private readonly collection: VersionedCollection<T>) {}

	async read(id: string): Promise<{ readonly value: T; readonly revision: string } | null> {
		const item = await this.collection.getVersioned(id);
		if (!item) return null;
		assertSupportedRecord<T>(item.value);
		return { value: item.value, revision: item.revision };
	}

	async create(id: string, value: T): Promise<RepositoryWrite<T>> {
		return this.write(id, null, value);
	}

	async replace(id: string, expectedRevision: string, value: T): Promise<RepositoryWrite<T>> {
		if (!expectedRevision) throw new TypeError('EXPECTED_REVISION_REQUIRED');
		return this.write(id, expectedRevision, value);
	}

	async remove(id: string, expectedRevision: string): Promise<boolean> {
		if (!expectedRevision) throw new TypeError('EXPECTED_REVISION_REQUIRED');
		return (await this.collection.compareAndDelete(id, expectedRevision)).applied;
	}

	private async write(
		id: string,
		expectedRevision: string | null,
		value: T,
	): Promise<RepositoryWrite<T>> {
		assertSupportedRecord<T>(value);
		assertBoundedRecord(value);
		let result: { applied: true; revision: string } | { applied: false };
		try {
			result = await this.collection.compareAndSet(id, expectedRevision, value);
		} catch {
			// A rejected bridge call can have an unknown outcome; never retry a write here.
			return { kind: 'unknown' };
		}
		return result.applied
			? { kind: 'written', revision: result.revision, value }
			: { kind: 'conflict' };
	}
}

/** A saga helper intentionally performs a single-record CAS, never a multi-record transaction. */
export async function compareAggregate<T extends ModelRecord>(
	repository: VersionedRepository<T>,
	id: string,
	expectedRevision: string,
	update: (current: T) => T,
): Promise<RepositoryWrite<T>> {
	const current = await repository.read(id);
	if (!current || current.revision !== expectedRevision) return { kind: 'conflict' };
	return repository.replace(id, current.revision, update(current.value));
}
