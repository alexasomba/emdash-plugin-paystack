import type { PluginContext } from 'emdash/plugin';
import { isPlainObject, type ModelRecord, type VersionedCollection } from './schema.js';

export const RECONCILIATION_TASK_NAME = 'reconcile';
export const RECONCILIATION_SCHEDULE = '* * * * *';
export const RECONCILIATION_HOOK_TIMEOUT_MS = 25_000;
export const RECONCILIATION_SELF_DEADLINE_MS = 20_000;
export const RECONCILIATION_BATCH_LIMIT = 25;
export const SCHEDULER_HEALTH_STALE_MS = 5 * 60_000;
export const RECONCILIATION_OVERDUE_MS = 15 * 60_000;
export const SCHEDULER_LEASE_MS = 45_000;
export const PROVIDER_RESET_FALLBACK_MS = 60_000;
export const PROVIDER_RESET_MAX_DELAY_MS = 72 * 60 * 60_000;

const HEALTH_DIGEST = 'a665812807c1b21e7424c43c8263074d0b0022ec404b881ae29a72c6eefa26fa';
const HEALTH_ID = `psk:v1:budgets:${HEALTH_DIGEST}`;
const WORKER_ID = /^[a-f0-9]{32}$/u;

export type ReconciliationQueue = 'intents' | 'inbox';

export interface SchedulerLease {
	readonly owner: string;
	readonly epoch: number;
	readonly expiresAt: number;
}

export interface SchedulerHealthRecord extends ModelRecord {
	readonly modelVersion: 1;
	readonly healthKind: 'paystack-reconciliation-scheduler';
	readonly leaseEpoch: number;
	readonly lease: SchedulerLease | null;
	readonly lastSuccessfulAt: number | null;
	readonly oldestDueIntentAt: number | null;
	readonly oldestDueInboxAt: number | null;
	readonly nextQueue: ReconciliationQueue;
	readonly providerCooldownUntil: number;
	readonly providerCooldownObservedAt: number | null;
	readonly expiresAt: number;
}

export type SchedulerClaim =
	| { readonly kind: 'claimed'; readonly record: SchedulerHealthRecord; readonly revision: string; readonly lease: SchedulerLease; readonly queue: ReconciliationQueue }
	| { readonly kind: 'busy' | 'unavailable' };

export interface SchedulerReadiness {
	readonly ready: boolean;
	readonly status: 'ready' | 'missing' | 'invalid' | 'stale' | 'overdue';
	readonly lastSuccessfulAt: number | null;
	readonly oldestDueAt: number | null;
	readonly providerCooldownUntil: number | null;
}

/** A single persistent, opaque health/lease record; never contains payment or customer data. */
export function schedulerHealthId(): string {
	return HEALTH_ID;
}

export function createSchedulerOwner(cryptoProvider: Crypto = globalThis.crypto): string | null {
	try {
		const bytes = cryptoProvider.getRandomValues(new Uint8Array(16));
		return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
	} catch { return null; }
}

export async function claimSchedulerHealth(
	collection: VersionedCollection<ModelRecord>, owner: string, nowMs: number,
): Promise<SchedulerClaim> {
	if (!WORKER_ID.test(owner) || !isValidNow(nowMs)) return { kind: 'unavailable' };
	let current: { readonly value: ModelRecord; readonly revision: string } | null;
	try { current = await collection.getVersioned(HEALTH_ID); } catch { return { kind: 'unavailable' }; }
	const prior = current ? current.value : emptySchedulerHealth();
	if (!isSchedulerHealthRecord(prior)) return { kind: 'unavailable' };
	if (prior.lease && prior.lease.expiresAt > nowMs) return { kind: 'busy' };
	const epoch = Math.max(prior.leaseEpoch, prior.lease?.epoch ?? 0) + 1;
	const expiresAt = nowMs + SCHEDULER_LEASE_MS;
	if (!Number.isSafeInteger(epoch) || !Number.isSafeInteger(expiresAt)) return { kind: 'unavailable' };
	const lease: SchedulerLease = Object.freeze({ owner, epoch, expiresAt });
	const next: SchedulerHealthRecord = Object.freeze({ ...prior, leaseEpoch: epoch, lease });
	let write: { applied: true; revision: string } | { applied: false };
	try { write = await collection.compareAndSet(HEALTH_ID, current?.revision ?? null, next); }
	catch { return { kind: 'unavailable' }; }
	if (!write.applied || !write.revision) return { kind: 'unavailable' };
	return { kind: 'claimed', record: next, revision: write.revision, lease, queue: prior.nextQueue };
}

/** Release only the current tick's fence; failed scans do not refresh readiness. */
export async function finishSchedulerHealth(
	collection: VersionedCollection<ModelRecord>,
	claim: Extract<SchedulerClaim, { kind: 'claimed' }>,
	input: {
		readonly nowMs: number;
		readonly scanSucceeded: boolean;
		readonly oldestDueAt: number | null;
		readonly providerCooldownUntil?: number;
	},
): Promise<boolean> {
	const { record, revision, lease, queue } = claim;
	if (!isSchedulerHealthRecord(record) || !isSchedulerLease(lease) || !isValidNow(input.nowMs) ||
		input.oldestDueAt !== null && !isValidNow(input.oldestDueAt) ||
		input.providerCooldownUntil !== undefined && !isValidNow(input.providerCooldownUntil) ||
		!sameLease(record.lease, lease) || input.nowMs >= lease.expiresAt) return false;
	const cooldown = record.providerCooldownUntil > input.nowMs ? record.providerCooldownUntil : 0;
	const reportedCooldown = input.providerCooldownUntil === undefined ? cooldown :
		Math.max(cooldown, input.providerCooldownUntil > input.nowMs ? input.providerCooldownUntil : 0);
	const next: SchedulerHealthRecord = Object.freeze({
		...record,
		lease: null,
		lastSuccessfulAt: input.scanSucceeded ? input.nowMs : record.lastSuccessfulAt,
		oldestDueIntentAt: queue === 'intents' && input.scanSucceeded ? input.oldestDueAt : record.oldestDueIntentAt,
		oldestDueInboxAt: queue === 'inbox' && input.scanSucceeded ? input.oldestDueAt : record.oldestDueInboxAt,
		nextQueue: input.scanSucceeded ? oppositeQueue(queue) : queue,
		providerCooldownUntil: reportedCooldown,
		providerCooldownObservedAt: input.providerCooldownUntil !== undefined && input.providerCooldownUntil > input.nowMs
			? input.nowMs
			: record.providerCooldownObservedAt,
	});
	try {
		const write = await collection.compareAndSet(HEALTH_ID, revision, next);
		return write.applied && Boolean(write.revision);
	} catch { return false; }
}

/** Read-only admission gate consumed by the site adapter in the dependent task. */
export async function readSchedulerReadiness(
	collection: VersionedCollection<ModelRecord>, nowMs: number,
): Promise<SchedulerReadiness> {
	if (!isValidNow(nowMs)) return readiness('invalid', null);
	let current: { readonly value: ModelRecord; readonly revision: string } | null;
	try { current = await collection.getVersioned(HEALTH_ID); } catch { return readiness('invalid', null); }
	if (!current) return readiness('missing', null);
	if (!isSchedulerHealthRecord(current.value)) return readiness('invalid', null);
	const record = current.value;
	const oldestDueAt = minTimestamp(record.oldestDueIntentAt, record.oldestDueInboxAt);
	const hasDueOverrun = oldestDueAt !== null && oldestDueAt <= nowMs && nowMs - oldestDueAt > RECONCILIATION_OVERDUE_MS;
	if (hasDueOverrun) return readiness('overdue', record, oldestDueAt);
	if (record.lastSuccessfulAt === null || record.lastSuccessfulAt > nowMs || nowMs - record.lastSuccessfulAt > SCHEDULER_HEALTH_STALE_MS) {
		return readiness('stale', record, oldestDueAt);
	}
	return readiness('ready', record, oldestDueAt);
}

/** Paystack documents x-ratelimit-reset in seconds; accept an epoch or a bounded delay. */
export function paystackCooldownUntil(resetHeader: string | null, nowMs: number): number {
	const fallback = nowMs + PROVIDER_RESET_FALLBACK_MS;
	if (!isValidNow(nowMs) || !resetHeader || resetHeader.length > 12 || !/^\d{1,12}$/u.test(resetHeader)) return fallback;
	const seconds = Number(resetHeader);
	if (!Number.isSafeInteger(seconds) || seconds < 1) return fallback;
	const resetAt = seconds >= 1_000_000_000 ? seconds * 1_000 : nowMs + seconds * 1_000;
	if (!Number.isSafeInteger(resetAt) || resetAt <= nowMs || resetAt - nowMs > PROVIDER_RESET_MAX_DELAY_MS) return fallback;
	return resetAt;
}

export function isSchedulerHealthRecord(value: unknown): value is SchedulerHealthRecord {
	if (!isPlainObject(value) || value.modelVersion !== 1 || value.healthKind !== 'paystack-reconciliation-scheduler' ||
		!Number.isSafeInteger(value.leaseEpoch) || typeof value.leaseEpoch !== 'number' || value.leaseEpoch < 0 ||
		value.lease !== null && !isSchedulerLease(value.lease) ||
		!nullableTimestamp(value.lastSuccessfulAt) || !nullableTimestamp(value.oldestDueIntentAt) ||
		!nullableTimestamp(value.oldestDueInboxAt) ||
		(value.nextQueue !== 'intents' && value.nextQueue !== 'inbox') ||
		!Number.isSafeInteger(value.providerCooldownUntil) || typeof value.providerCooldownUntil !== 'number' || value.providerCooldownUntil < 0 ||
		!nullableTimestamp(value.providerCooldownObservedAt) ||
		value.expiresAt !== Number.MAX_SAFE_INTEGER) return false;
	const allowed = new Set([
		'modelVersion', 'healthKind', 'leaseEpoch', 'lease', 'lastSuccessfulAt', 'oldestDueIntentAt', 'oldestDueInboxAt',
		'nextQueue', 'providerCooldownUntil', 'providerCooldownObservedAt', 'expiresAt',
	]);
	return Object.keys(value).every((key) => allowed.has(key));
}

function emptySchedulerHealth(): SchedulerHealthRecord {
	return Object.freeze({
		modelVersion: 1,
		healthKind: 'paystack-reconciliation-scheduler',
		leaseEpoch: 0,
		lease: null,
		lastSuccessfulAt: null,
		oldestDueIntentAt: null,
		oldestDueInboxAt: null,
		nextQueue: 'intents',
		providerCooldownUntil: 0,
		providerCooldownObservedAt: null,
		expiresAt: Number.MAX_SAFE_INTEGER,
	});
}

function isSchedulerLease(value: unknown): value is SchedulerLease {
	return isPlainObject(value) && WORKER_ID.test(String(value.owner)) &&
		Number.isSafeInteger(value.epoch) && typeof value.epoch === 'number' && value.epoch > 0 &&
		Number.isSafeInteger(value.expiresAt) && typeof value.expiresAt === 'number' && value.expiresAt > 0;
}

function sameLease(left: SchedulerLease | null, right: SchedulerLease): boolean {
	return left !== null && left.owner === right.owner && left.epoch === right.epoch && left.expiresAt === right.expiresAt;
}

function readiness(
	status: SchedulerReadiness['status'], record: SchedulerHealthRecord | null, oldestDueAt: number | null = null,
): SchedulerReadiness {
	return Object.freeze({
		ready: status === 'ready', status,
		lastSuccessfulAt: record?.lastSuccessfulAt ?? null,
		oldestDueAt,
		providerCooldownUntil: record && record.providerCooldownUntil > 0 ? record.providerCooldownUntil : null,
	});
}

function minTimestamp(left: number | null, right: number | null): number | null {
	if (left === null) return right;
	if (right === null) return left;
	return Math.min(left, right);
}

function oppositeQueue(queue: ReconciliationQueue): ReconciliationQueue {
	return queue === 'intents' ? 'inbox' : 'intents';
}

function nullableTimestamp(value: unknown): value is number | null {
	return value === null || isValidNow(value);
}

function isValidNow(value: unknown): value is number {
	return Number.isSafeInteger(value) && typeof value === 'number' && value >= 0;
}

/** A narrow wrapper lets each health read/write be metered as its own bounded bridge stage. */
export function schedulerHealthCollection(ctx: PluginContext): VersionedCollection<ModelRecord> | null {
	const collection = ctx.storage.budgets;
	return collection ? collection as unknown as VersionedCollection<ModelRecord> : null;
}
