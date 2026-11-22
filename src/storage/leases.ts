import { VersionedRepository, type RepositoryWrite } from './aggregates.js';
import type { ModelRecord } from './schema.js';

export const LEASE_DURATION_MS = 45_000;

export type Lease = {
	readonly owner: string;
	readonly epoch: number;
	readonly expiresAt: number;
};

export type LeaseRecord = ModelRecord & { readonly lease?: Lease | null };

export type LeaseClaim<T extends LeaseRecord> =
	| { readonly kind: 'claimed'; readonly value: T; readonly revision: string; readonly lease: Lease }
	| { readonly kind: 'busy' }
	| { readonly kind: 'missing' }
	| { readonly kind: 'unknown' };

export async function claimLease<T extends LeaseRecord>(
	repository: VersionedRepository<T>,
	id: string,
	owner: string,
	nowMs: number,
): Promise<LeaseClaim<T>> {
	if (!/^[A-Za-z0-9_-]{16,96}$/.test(owner) || !Number.isSafeInteger(nowMs) || nowMs < 0) {
		return { kind: 'unknown' };
	}
	const current = await repository.read(id);
	if (!current) return { kind: 'missing' };
	const prior = current.value.lease;
	if (prior && prior.expiresAt > nowMs) return { kind: 'busy' };
	const epoch = prior ? prior.epoch + 1 : 1;
	if (!Number.isSafeInteger(epoch) || epoch < 1) return { kind: 'unknown' };
	const lease: Lease = { owner, epoch, expiresAt: nowMs + LEASE_DURATION_MS };
	const updated = { ...current.value, lease } as T;
	const result: RepositoryWrite<T> = await repository.replace(id, current.revision, updated);
	if (result.kind === 'written') {
		return { kind: 'claimed', value: result.value, revision: result.revision, lease };
	}
	return result.kind === 'conflict' ? { kind: 'busy' } : { kind: 'unknown' };
}

export function ownsLease(record: LeaseRecord, expected: Pick<Lease, 'owner' | 'epoch'>, nowMs: number): boolean {
	const lease = record.lease;
	return Boolean(
		lease &&
		lease.owner === expected.owner &&
		lease.epoch === expected.epoch &&
		lease.expiresAt > nowMs,
	);
}
