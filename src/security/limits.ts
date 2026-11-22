import type { SettingsPort } from '../domain/configuration.js';
import type { VersionedCollection } from '../storage/schema.js';

export const NORMAL_BRIDGE_CALL_LIMIT = 8;
export const HARD_BRIDGE_CALL_LIMIT = 10;
export const SELF_DEADLINE_MS = 20_000;
export const LOCAL_PROVIDER_WAIT_MS = 8_000;

export type BudgetStage = 'admission' | 'action' | 'provider' | 'webhook' | 'reconciliation' | 'admin' | 'public_render';
export type BridgeKind = 'settings' | 'storage' | 'http' | 'cron' | 'log';
export type BudgetOperation =
	| 'settings.read'
	| 'settings.write'
	| 'storage.read'
	| 'storage.query'
	| 'storage.create'
	| 'storage.write'
	| 'storage.delete'
	| 'http.fetch'
	| 'cron.schedule'
	| 'cron.list'
	| 'log.write';

export interface BudgetCall {
	readonly kind: BridgeKind;
	readonly operation: BudgetOperation;
	readonly ordinal: number;
	readonly elapsedMs: number;
}

export type BudgetStopReason = 'rpc_limit' | 'deadline';

export class StageBudgetExceeded extends Error {
	constructor(readonly reason: BudgetStopReason, readonly operationStarted = false) {
		super('stage budget exhausted');
		this.name = 'StageBudgetExceeded';
	}
}

export class StageBudget {
	private readonly startedAt: number;
	private readonly deadlineAt: number;
	private readonly calls: BudgetCall[] = [];

	constructor(
		readonly stage: BudgetStage,
		private readonly now: () => number,
		options: { readonly maxCalls?: number; readonly deadlineMs?: number } = {},
	) {
		const maxCalls = options.maxCalls ?? NORMAL_BRIDGE_CALL_LIMIT;
		const deadlineMs = options.deadlineMs ?? SELF_DEADLINE_MS;
		if (!Number.isSafeInteger(maxCalls) || maxCalls < 1 || maxCalls > NORMAL_BRIDGE_CALL_LIMIT) {
			throw new RangeError('maxCalls must preserve the two-call host reserve');
		}
		if (!Number.isSafeInteger(deadlineMs) || deadlineMs < 1 || deadlineMs > SELF_DEADLINE_MS) {
			throw new RangeError('deadlineMs exceeds the approved self deadline');
		}
		this.startedAt = now();
		if (!Number.isFinite(this.startedAt)) throw new RangeError('clock must return finite milliseconds');
		this.deadlineAt = this.startedAt + deadlineMs;
		this.maxCalls = maxCalls;
	}

	private readonly maxCalls: number;

	get count(): number {
		return this.calls.length;
	}

	get elapsedMs(): number {
		const current = this.now();
		return Number.isFinite(current) ? Math.max(0, current - this.startedAt) : SELF_DEADLINE_MS;
	}

	get snapshot(): readonly BudgetCall[] {
		return Object.freeze([...this.calls]);
	}

	async run<T>(kind: BridgeKind, operation: BudgetOperation, effect: () => Promise<T> | T): Promise<T> {
		const now = this.now();
		if (!Number.isFinite(now) || now < this.startedAt || now >= this.deadlineAt) throw new StageBudgetExceeded('deadline');
		if (this.calls.length >= this.maxCalls) throw new StageBudgetExceeded('rpc_limit');
		this.calls.push(Object.freeze({ kind, operation, ordinal: this.calls.length + 1, elapsedMs: Math.max(0, now - this.startedAt) }));
		const result = await effect();
		const completedAt = this.now();
		if (!Number.isFinite(completedAt) || completedAt < now || completedAt >= this.deadlineAt) {
			// The host operation may have committed. Callers must preserve unknown effects and never retry writes blindly.
			throw new StageBudgetExceeded('deadline', true);
		}
		return result;
	}
}

export type ProviderWaitResult<T> =
	| { readonly kind: 'completed'; readonly value: T }
	| { readonly kind: 'failed' }
	| { readonly kind: 'wait_expired' };

/** The timer bounds local waiting only; the underlying host request is not canceled. */
export async function waitForProvider<T>(promise: Promise<T>): Promise<ProviderWaitResult<T>> {
	let timer: ReturnType<typeof setTimeout> | undefined;
	const timeout = new Promise<ProviderWaitResult<T>>((resolve) => {
		timer = setTimeout(() => resolve({ kind: 'wait_expired' }), LOCAL_PROVIDER_WAIT_MS);
	});
	try {
		const completed = promise.then<ProviderWaitResult<T>, ProviderWaitResult<T>>(
			(value) => ({ kind: 'completed', value }),
			() => ({ kind: 'failed' }),
		);
		return await Promise.race([completed, timeout]);
	} finally {
		if (timer !== undefined) clearTimeout(timer);
	}
}

export interface SafeBudgetLog {
	readonly event: 'stage_budget_stopped' | 'operation_failed';
	readonly stage: BudgetStage;
	readonly operation: BudgetOperation;
	readonly code: 'rpc_limit' | 'deadline' | 'operation_failed';
	readonly elapsedMs: number;
	readonly bridgeCalls: number;
}

export function budgetLog(
	event: SafeBudgetLog['event'],
	stage: BudgetStage,
	operation: BudgetOperation,
	code: SafeBudgetLog['code'],
	budget: StageBudget,
): SafeBudgetLog {
	return Object.freeze({
		event,
		stage,
		operation,
		code,
		elapsedMs: Math.max(0, Math.min(SELF_DEADLINE_MS, Math.floor(budget.elapsedMs))),
		bridgeCalls: Math.min(HARD_BRIDGE_CALL_LIMIT, budget.count),
	});
}

/** Meter the underlying bridge operation once, including an attempted write with an unknown outcome. */
export function meterCollection<T>(collection: VersionedCollection<T>, budget: StageBudget): VersionedCollection<T> {
	return {
		getVersioned: (id) => budget.run('storage', 'storage.read', () => collection.getVersioned(id)),
		compareAndSet: (id, revision, value) =>
			budget.run('storage', revision === null ? 'storage.create' : 'storage.write',
				() => collection.compareAndSet(id, revision, value)),
		compareAndDelete: (id, revision) =>
			budget.run('storage', 'storage.delete', () => collection.compareAndDelete(id, revision)),
		query: (options) => budget.run('storage', 'storage.query', () => collection.query(options)),
	};
}

export function meterSettings(settings: SettingsPort, budget: StageBudget): SettingsPort {
	return {
		getVersioned: <T>(key: string) => budget.run('settings', 'settings.read', () => settings.getVersioned<T>(key)),
		compareAndSet: (key, revision, value) =>
			budget.run('settings', 'settings.write', () => settings.compareAndSet(key, revision, value)),
	};
}
