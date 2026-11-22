import type { PluginContext, SandboxedRouteContext } from 'emdash/plugin';
import { verifyPaystackTransactionFromContext } from '../domain/verification.js';
import { meterCollection, StageBudget } from '../security/limits.js';
import {
	MAX_WEBHOOK_INBOX_RECORD_BYTES,
	isWebhookInboxRecord,
	type WebhookInboxRecord,
} from '../storage/inbox.js';
import { deterministicRecordId, isPlainObject, type ModelRecord, type VersionedCollection } from '../storage/schema.js';
import { parsePaystackReference } from '../provider/paystack-reference.js';
import { domainError, domainOk, type DomainResult } from './response.js';

const EVENT_ID = /^psk:v1:inbox:[a-f0-9]{64}$/u;
const ATTEMPT_ID = /^psk:v1:attempts:[a-f0-9]{64}$/u;
const CLAIM_LEASE_MS = 45_000;

export interface ReconciliationResponse {
	readonly processed: number;
	readonly remainingUnresolved: number;
}

export interface PaystackReconciliationDependencies {
	readonly pluginId: string;
	readonly inbox: VersionedCollection<ModelRecord>;
	readonly verify: (input: {
		readonly intentId: string;
		readonly attemptId: string;
		readonly expectedReference: string;
		readonly expectedMerchantProfile: string;
		readonly expectedEnvironment: 'test' | 'live';
		readonly expectedCredentialVersion: number;
		readonly expectedAttemptOrdinal: number;
		readonly expectedResourceId?: string;
		readonly forceVerification: boolean;
	}) => ReturnType<typeof verifyPaystackTransactionFromContext>;
	readonly now?: () => number;
}

/** Privileged, exact-event reconciliation. Provider verification remains the only path to paid. */
export async function handlePaystackReconciliation(
	input: unknown,
	dependencies: PaystackReconciliationDependencies,
): Promise<DomainResult<ReconciliationResponse>> {
	if (!dependencies.pluginId || !isReconcileRequest(input)) return domainError('validation_error');
	const now = dependencies.now ?? Date.now;
	const nowMs = now();
	if (!Number.isSafeInteger(nowMs) || nowMs < 0) return domainError('storage_unavailable');

	let current: { readonly value: ModelRecord; readonly revision: string } | null;
	try { current = await dependencies.inbox.getVersioned(input.eventId); }
	catch { return domainError('storage_unavailable'); }
	if (!current || !current.revision || !isWebhookInboxRecord(current.value) ||
		deterministicRecordId('inbox', current.value.semanticKey) !== input.eventId ||
		input.attemptId !== undefined && current.value.attemptId !== input.attemptId) return domainError('review_required');
	const event = current.value;
	if (event.state === 'done') return domainOk({ processed: 0, remainingUnresolved: 0 });
	if (event.state === 'review') return domainOk({ processed: 0, remainingUnresolved: 1 });
	if (event.state === 'processing' && event.dueAt > nowMs) return domainOk({ processed: 0, remainingUnresolved: 1 });

	const referenceIdentity = parsePaystackReference(event.reference);
	if (!event.intentId || !event.attemptId || !referenceIdentity || referenceIdentity.intentId !== event.intentId) {
		const marked = await updateInbox(dependencies.inbox, input.eventId, current.revision, event, 'review', nowMs);
		return marked ? domainError('review_required') : domainError('storage_unavailable');
	}
	const nextEpoch = event.leaseEpoch + 1;
	const dueAt = nowMs + CLAIM_LEASE_MS;
	if (!Number.isSafeInteger(nextEpoch) || !Number.isSafeInteger(dueAt)) return domainError('storage_unavailable');
	const claimed: WebhookInboxRecord = Object.freeze({ ...event, state: 'processing', leaseEpoch: nextEpoch, dueAt });
	const claim = await writeInbox(dependencies.inbox, input.eventId, current.revision, claimed);
	if (claim.kind !== 'written') return domainError('storage_unavailable');

	let verified;
	try {
		verified = await dependencies.verify({
			intentId: event.intentId,
			attemptId: event.attemptId,
			expectedReference: event.reference,
			expectedMerchantProfile: event.profileId,
			expectedEnvironment: event.environment,
			expectedCredentialVersion: event.credentialVersion,
			expectedAttemptOrdinal: referenceIdentity.attemptOrdinal,
			...(event.providerResourceId ? { expectedResourceId: event.providerResourceId } : {}),
			// A repeated positive delivery resumes the durable inbox without an extra provider read.
			// Other signed charge observations may verify a later reversal/final state.
			forceVerification: event.eventType !== 'charge.success',
		});
	} catch { return domainError('provider_unavailable'); }

	if (verified.kind === 'unavailable') return domainError('provider_unavailable');
	if (verified.kind === 'conflict' || verified.kind === 'invalid' || verified.kind === 'not_found') {
		const marked = await updateInbox(dependencies.inbox, input.eventId, claim.revision, claimed, 'review', now());
		return marked ? domainError('review_required') : domainError('storage_unavailable');
	}
	const terminalState = verified.kind === 'review_required' ? 'review' : 'done';
	const completed = await updateInbox(dependencies.inbox, input.eventId, claim.revision, claimed, terminalState, now());
	if (!completed) return domainError('storage_unavailable');
	return domainOk({
		processed: 1,
		remainingUnresolved: verified.kind === 'pending' || verified.kind === 'review_required' ? 1 : 0,
	});
}

/** Admin route: EmDash enforces session, plugins:manage RBAC, JSON parsing and mutation CSRF. */
export async function reconciliationRoute(routeCtx: SandboxedRouteContext, ctx: PluginContext): Promise<unknown> {
	let budget: StageBudget;
	try { budget = new StageBudget('reconciliation', () => Date.now()); }
	catch { return domainError('storage_unavailable'); }
	const collection = ctx.storage.inbox as unknown as VersionedCollection<ModelRecord>;
	const inbox = meterCollection(collection, budget);

	let result: DomainResult<ReconciliationResponse>;
	try {
		result = await handlePaystackReconciliation(routeCtx.input, {
			pluginId: ctx.plugin.id,
			inbox,
			verify: (input) => verifyPaystackTransactionFromContext(input, ctx, budget),
		});
	} catch {
		result = domainError('storage_unavailable');
	}
	return result.ok ? domainOk(result.value) : domainError(result.error.code);
}

function isReconcileRequest(value: unknown): value is { eventId: string; attemptId?: string; limit?: number } {
	return isPlainObject(value) && Object.hasOwn(value, 'eventId') &&
		Object.keys(value).every((key) => ['eventId', 'attemptId', 'limit'].includes(key)) &&
		typeof value.eventId === 'string' && EVENT_ID.test(value.eventId) &&
		(value.attemptId === undefined || typeof value.attemptId === 'string' && ATTEMPT_ID.test(value.attemptId)) &&
		(value.limit === undefined || value.limit === 1);
}

async function updateInbox(
	collection: VersionedCollection<ModelRecord>,
	id: string,
	expectedRevision: string,
	current: WebhookInboxRecord,
	state: 'done' | 'review',
	nowMs: number,
): Promise<boolean> {
	if (!Number.isSafeInteger(nowMs) || nowMs < 0) return false;
	const updated: WebhookInboxRecord = Object.freeze({
		...current,
		state,
		dueAt: state === 'done' ? Number.MAX_SAFE_INTEGER : nowMs,
		leaseEpoch: current.leaseEpoch + 1,
	});
	if (!Number.isSafeInteger(updated.leaseEpoch) || !isWebhookInboxRecord(updated) ||
		new TextEncoder().encode(JSON.stringify(updated)).byteLength > MAX_WEBHOOK_INBOX_RECORD_BYTES) return false;
	return (await writeInbox(collection, id, expectedRevision, updated)).kind === 'written';
}

async function writeInbox(
	collection: VersionedCollection<ModelRecord>,
	id: string,
	expectedRevision: string,
	updated: WebhookInboxRecord,
): Promise<{ readonly kind: 'written'; readonly revision: string } | { readonly kind: 'conflict' | 'unknown' }> {
	try {
		const result = await collection.compareAndSet(id, expectedRevision, updated);
		return result.applied && result.revision
			? { kind: 'written', revision: result.revision }
			: { kind: 'conflict' };
	} catch {
		// Confirm an applied-but-lost inbox transition with one exact read; never retry the write.
		try {
			const observed = await collection.getVersioned(id);
			return observed?.revision && isWebhookInboxRecord(observed.value) &&
				observed.value.semanticKey === updated.semanticKey && observed.value.state === updated.state &&
				observed.value.leaseEpoch === updated.leaseEpoch
				? { kind: 'written', revision: observed.revision }
				: { kind: 'unknown' };
		} catch { return { kind: 'unknown' }; }
	}
}
