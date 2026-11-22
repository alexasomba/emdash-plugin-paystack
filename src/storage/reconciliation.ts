import type { CronEvent, LifecycleEvent, PluginContext } from 'emdash/plugin';
import { verifyPaystackTransaction } from '../domain/verification.js';
import { meterCollection, StageBudget } from '../security/limits.js';
import { handlePaystackReconciliation } from '../routes/reconciliation.js';
import { isWebhookInboxRecord } from './inbox.js';
import {
	claimSchedulerHealth,
	createSchedulerOwner,
	finishSchedulerHealth,
	paystackCooldownUntil,
	RECONCILIATION_BATCH_LIMIT,
	RECONCILIATION_SCHEDULE,
	RECONCILIATION_SELF_DEADLINE_MS,
	RECONCILIATION_TASK_NAME,
	schedulerHealthCollection,
	type ReconciliationQueue,
} from './scheduler-health.js';
import { isProviderIntentRecord, type ProviderAttemptRecord, type ProviderIntentRecord } from './provider-work.js';
import { deterministicRecordId, type ModelRecord, type VersionedCollection } from './schema.js';
import type { SettingsPort } from '../domain/configuration.js';

const DUE_INTENT_STATES = ['initializing', 'unknown', 'requires_action'] as const;
const DUE_INBOX_STATES = ['accepted', 'processing'] as const;
const INTENT_ID = /^psk:v1:intents:[a-f0-9]{64}$/u;
const ATTEMPT_ID = /^psk:v1:attempts:[a-f0-9]{64}$/u;

interface DueSelection {
	readonly oldestDueAt: number | null;
	readonly item: { readonly id: string; readonly data: ModelRecord } | null;
}

/** Keep the host schedule durable across install/activation and cancel it on deactivation. */
export async function schedulePaystackReconciliation(_event: LifecycleEvent, ctx: PluginContext): Promise<void> {
	if (!ctx.cron) return;
	const budget = new StageBudget('reconciliation', Date.now, { maxCalls: 1, deadlineMs: 5_000 });
	try {
		await budget.run('cron', 'cron.schedule', () => ctx.cron!.schedule(RECONCILIATION_TASK_NAME, {
			schedule: RECONCILIATION_SCHEDULE,
		}));
	} catch {
		// Missing/stale health makes payment admission fail closed; lifecycle hooks do not fake success.
	}
}

export async function cancelPaystackReconciliation(_event: LifecycleEvent, ctx: PluginContext): Promise<void> {
	if (!ctx.cron) return;
	const budget = new StageBudget('reconciliation', Date.now, { maxCalls: 1, deadlineMs: 5_000 });
	try {
		await budget.run('cron', 'cron.schedule', () => ctx.cron!.cancel(RECONCILIATION_TASK_NAME));
	} catch {
		// A later activation upserts the same named schedule.
	}
}

/** One UTC invocation inspects at most25 due rows and performs at mostone provider read. */
export async function runPaystackReconciliationTick(event: CronEvent, ctx: PluginContext): Promise<void> {
	if (event.name !== RECONCILIATION_TASK_NAME || !ctx.http) return;
	const now = Date.now;
	const startedAt = now();
	if (!isValidTimestamp(startedAt)) return;
	const health = schedulerHealthCollection(ctx);
	if (!health) return;
	const owner = createSchedulerOwner();
	if (!owner) return;

	let claim = { kind: 'unavailable' as const } as Awaited<ReturnType<typeof claimSchedulerHealth>>;
	const healthClaimBudget = new StageBudget('reconciliation', now, { maxCalls: 2, deadlineMs: 5_000 });
	try {
		claim = await claimSchedulerHealth(meterCollection(health, healthClaimBudget), owner, startedAt);
	} catch { return; }
	if (claim.kind !== 'claimed') return;

	let scanSucceeded = false;
	let oldestDueAt: number | null = null;
	let providerCooldownUntil: number | undefined;
	try {
		const budget = new StageBudget('reconciliation', now, {
			maxCalls: 8,
			deadlineMs: RECONCILIATION_SELF_DEADLINE_MS,
		});
		const rawCollection = claim.queue === 'intents'
			? ctx.storage.intents as unknown as VersionedCollection<ModelRecord>
			: ctx.storage.inbox as unknown as VersionedCollection<ModelRecord>;
		const selection = await selectDue(rawCollection, claim.queue, startedAt, budget);
		oldestDueAt = selection.oldestDueAt;
		scanSucceeded = true;

		if (selection.item && claim.record.providerCooldownUntil <= startedAt) {
			const capture = { cooldownUntil: undefined as number | undefined };
			if (claim.queue === 'intents') {
				await verifyIntent(selection.item, ctx, budget, capture, now);
			} else {
				await reconcileInbox(selection.item, ctx, budget, capture, now);
			}
			providerCooldownUntil = capture.cooldownUntil;
		}
	} catch {
		// Preserve the old heartbeat whenever the scan or processing stage throws.
		scanSucceeded = false;
	}

	const finishedAt = now();
	if (!isValidTimestamp(finishedAt)) return;
	const finishBudget = new StageBudget('reconciliation', now, { maxCalls: 1, deadlineMs: 5_000 });
	try {
		await finishSchedulerHealth(
			meterCollection(health, finishBudget), claim,
			{
				nowMs: finishedAt,
				scanSucceeded,
				oldestDueAt,
				...(providerCooldownUntil === undefined ? {} : { providerCooldownUntil }),
			},
		);
	} catch {
		// A failed health write leaves only the short lease; readiness cannot advance from it.
	}
}

async function selectDue(
	collection: VersionedCollection<ModelRecord>, queue: ReconciliationQueue, nowMs: number, budget: StageBudget,
): Promise<DueSelection> {
	const options = queue === 'intents'
		? {
			where: { state: { in: [...DUE_INTENT_STATES] }, nextRunAt: { lte: nowMs } },
			orderBy: { nextRunAt: 'asc' as const }, limit: RECONCILIATION_BATCH_LIMIT,
		}
		: {
			where: { state: { in: [...DUE_INBOX_STATES] }, dueAt: { lte: nowMs } },
			orderBy: { dueAt: 'asc' as const }, limit: RECONCILIATION_BATCH_LIMIT,
		};
	const page = await budget.run('storage', 'storage.query', () => collection.query(options));
	const dueTimes = page.items.map(({ data }) => queue === 'intents' ? data.nextRunAt : data.dueAt)
		.filter(isValidTimestamp);
	const oldestDueAt = dueTimes.length ? Math.min(...dueTimes) : null;
	for (const item of page.items) {
		if (queue === 'intents' ? isDueIntent(item.id, item.data, nowMs) : isDueInbox(item.id, item.data, nowMs)) {
			return { oldestDueAt, item };
		}
	}
	return { oldestDueAt, item: null };
}

async function verifyIntent(
	item: { readonly id: string; readonly data: ModelRecord }, ctx: PluginContext, budget: StageBudget,
	capture: { cooldownUntil: number | undefined }, now: () => number,
): Promise<void> {
	if (!INTENT_ID.test(item.id) || !isProviderIntentRecord(item.data)) return;
	const attempt = item.data.attempts.find((candidate) => candidate.id === item.data.currentAttemptId);
	if (!attempt || !attempt.createTransmissionStarted || typeof attempt.providerReference !== 'string') return;
	await verifyPaystackTransaction({ intentId: item.id, attemptId: attempt.id }, {
		pluginId: ctx.plugin.id,
		settings: settingsPort(ctx),
		intents: ctx.storage.intents as unknown as VersionedCollection<ModelRecord>,
		fetch: (url, init) => fetchWithCooldown(url, init, ctx, capture, now),
		budget,
	});
}

async function reconcileInbox(
	item: { readonly id: string; readonly data: ModelRecord }, ctx: PluginContext, budget: StageBudget,
	capture: { cooldownUntil: number | undefined }, now: () => number,
): Promise<void> {
	if (!isDueInbox(item.id, item.data, now())) return;
	const inbox = meterCollection(ctx.storage.inbox as unknown as VersionedCollection<ModelRecord>, budget);
	await handlePaystackReconciliation({ eventId: item.id, ...(typeof item.data.attemptId === 'string' ? { attemptId: item.data.attemptId } : {}), limit: 1 }, {
		pluginId: ctx.plugin.id,
		inbox,
		verify: (input) => verifyPaystackTransaction(input, {
			pluginId: ctx.plugin.id,
			settings: settingsPort(ctx),
			intents: ctx.storage.intents as unknown as VersionedCollection<ModelRecord>,
			fetch: (url, init) => fetchWithCooldown(url, init, ctx, capture, now),
			budget,
		}),
		now,
	});
}

export function isDueIntent(id: string, data: ModelRecord, nowMs: number): data is ProviderIntentRecord & ModelRecord {
	if (!INTENT_ID.test(id) || !isProviderIntentRecord(data) ||
		(data.state !== 'initializing' && data.state !== 'unknown' && data.state !== 'requires_action') || data.nextRunAt > nowMs) return false;
	const attempt = data.attempts.find((candidate) => candidate.id === data.currentAttemptId) as ProviderAttemptRecord | undefined;
	return Boolean(attempt && ATTEMPT_ID.test(attempt.id) && attempt.createTransmissionStarted &&
		typeof attempt.providerReference === 'string' && attempt.providerReference.length > 0 &&
		attempt.nextRunAt <= nowMs && attempt.state !== 'review_required' && attempt.state !== 'succeeded');
}

function isDueInbox(id: string, data: ModelRecord, nowMs: number): boolean {
	return typeof id === 'string' && /^psk:v1:inbox:[a-f0-9]{64}$/u.test(id) && isWebhookInboxRecord(data) &&
		deterministicRecordId('inbox', data.semanticKey) === id &&
		(data.state === 'accepted' || data.state === 'processing') && data.dueAt <= nowMs;
}

function settingsPort(ctx: PluginContext): SettingsPort {
	return {
		getVersioned: <T>(key: string) => ctx.settings.getVersioned<T>(key),
		compareAndSet: (key, expectedRevision, value) => ctx.settings.compareAndSet(key, expectedRevision, value),
	};
}

async function fetchWithCooldown(
	url: string, init: RequestInit | undefined, ctx: PluginContext,
	capture: { cooldownUntil: number | undefined }, now: () => number,
): Promise<Response> {
	const response = await ctx.http!.fetch(url, init);
	if (response.status === 429) {
		capture.cooldownUntil = paystackCooldownUntil(response.headers.get('x-ratelimit-reset'), now());
	}
	return response;
}

function isValidTimestamp(value: unknown): value is number {
	return Number.isSafeInteger(value) && typeof value === 'number' && value >= 0;
}
