import { hasExactKeys } from '../security/json.js';
import type { PluginContext, SandboxedRequest, SandboxedRouteContext } from 'emdash/plugin';
import { isSafeErrorCode, mapSafeErrorCode, type SafeErrorCode } from '../domain/errors.js';
import { isConsistentPaidAggregate } from '../domain/verification.js';
import type { SettingsPort } from '../domain/configuration.js';
import { createPaystackCheckout, isHttpsSameSiteCallback, parsePaystackCheckoutUrl, type PaystackCreateDependencies } from '../provider/paystack.js';
import type { NonceRecord } from '../security/attestation.js';
import { meterCollection, meterSettings, StageBudget, StageBudgetExceeded } from '../security/limits.js';
import { isAdmissionIntentRecord, type AdmissionIntentRecord } from '../storage/admission.js';
import {
	isProviderIntentRecord,
	isProviderNextAction,
	type ProviderNextAction,
} from '../storage/provider-work.js';
import { isPlainObject, type ModelRecord, type VersionedCollection } from '../storage/schema.js';
import { authenticatePaymentRoute, decryptIntentSnapshot, type ConfigurationRuntime } from './site.js';
import { domainError, domainOk } from './response.js';

const ACTION_ROUTE = 'payments/action';
const INTENT_ID = /^psk:v1:intents:[a-f0-9]{64}$/u;
const ATTEMPT_ID = /^psk:v1:attempts:[a-f0-9]{64}$/u;
const IDENTIFIER = /^[A-Za-z0-9_-]{1,255}$/u;
const ATTEMPT_STATES = new Set([
	'created', 'initializing', 'requires_action', 'pending', 'unknown',	'verified_paid',
	'verified_failed', 'verified_canceled', 'review_required',
]);
const DELIVERY_STATES = new Set(['not_eligible', 'pending', 'acknowledged']);

export interface SiteActionDependencies {
	readonly pluginId: string;
	readonly settings: SettingsPort;
	readonly nonces: Pick<VersionedCollection<NonceRecord>, 'compareAndSet'>;
	readonly intents: Pick<VersionedCollection<ModelRecord>, 'getVersioned'>;
	/** Unwrapped host ports; the provider worker applies its own bounded stage budget. */
	readonly provider?: Omit<PaystackCreateDependencies, 'pluginId'>;
	readonly now?: () => number;
}

interface TrustedActionRequest {
	readonly schemaVersion: '1.0';
	readonly siteId: string;
	readonly subject: { readonly kind: 'guest' | 'member'; readonly id: string };
	readonly merchantProfile: string;
	readonly intentId: string;
	readonly attemptId: string;
	readonly actionId: string;
	readonly siteOrigin: string;
	readonly callbackUrl: string;
	readonly expectedEnvironment?: 'test' | 'live';
}

interface OwnedActionIntent {
	readonly identityHmac: string;
	readonly siteId: string;
	readonly merchantId: string;
	readonly merchantProfile: string;
	readonly environment: 'test' | 'live';
	readonly credentialVersion: number;
	readonly state: string;
	readonly currentAttemptId: string;
	readonly deliveryState: string;
	readonly attempts: readonly {
		readonly id: string;
		readonly state: string;
		readonly createTransmissionStarted?: boolean;
		readonly nextAction?: unknown;
	}[];
}

/** Site-attested continuation for the exact currently owned provider action. */
export async function siteActionRoute(routeCtx: SandboxedRouteContext, ctx: PluginContext): Promise<unknown> {
	return siteOwnedRoute(routeCtx, ctx, 'action');
}

export async function siteStatusRoute(routeCtx: SandboxedRouteContext, ctx: PluginContext): Promise<unknown> {
	return siteOwnedRoute(routeCtx, ctx, 'status');
}

async function siteOwnedRoute(routeCtx: SandboxedRouteContext, ctx: PluginContext, operation: 'action' | 'status'): Promise<unknown> {
	const budget = new StageBudget('action', () => Date.now());
	const settings = meterSettings(ctx.settings, budget);
	const wrapCollection = <T>(name: string) => meterCollection(ctx.storage[name] as VersionedCollection<T>, budget);
	const dependencies: SiteActionDependencies = {
		pluginId: ctx.plugin.id,
		settings,
		nonces: wrapCollection<NonceRecord>('nonces'),
		intents: wrapCollection<ModelRecord>('intents'),
		...(ctx.http ? { provider: {
			settings: ctx.settings as unknown as SettingsPort,
			intents: ctx.storage.intents as unknown as VersionedCollection<ModelRecord>,
			budgets: ctx.storage.budgets as unknown as VersionedCollection<ModelRecord>,
			fetch: (url, init) => ctx.http!.fetch(url, init),
		} } : {}),
		now: () => Date.now(),
	};
	try {
		return operation === 'action' ? await handleSiteAction(routeCtx.input, routeCtx.request, dependencies) :
			await handleSiteStatus(routeCtx.input, routeCtx.request, dependencies);
	} catch (error) {
		const code = error instanceof StageBudgetExceeded ? 'storage_unavailable' : 'temporary_unavailable';
		return domainError(safeActionErrorCode(code));
	}
}

/** Domain boundary is exported for exact-byte ownership and action-state tests. */
export async function handleSiteAction(
	rawBody: unknown,
	request: SandboxedRequest,
	dependencies: SiteActionDependencies,
): Promise<unknown> {
	const authenticated = await authenticatePaymentRoute(ACTION_ROUTE, rawBody, request, dependencies);
	if (!authenticated.ok) return authenticated;
	const { runtime, body, siteId } = authenticated.value;
	const parsed = parseTrustedActionRequest(body, siteId);
	if (!parsed.ok) return domainError(parsed.code);
	const owned = await readOwnedIntent(parsed.value, runtime, dependencies);
	if (!owned.ok) return owned;
	const { intent, snapshot } = owned.value;
	if (parsed.value.expectedEnvironment !== undefined && intent.environment !== parsed.value.expectedEnvironment) return domainError('forbidden');
	if (intent.currentAttemptId !== parsed.value.attemptId || intent.state !== (intent.attempts.find((attempt) =>
		attempt.id === intent.currentAttemptId)?.state)) return domainError('forbidden');
	const attempt = intent.attempts.find((item) => item.id === intent.currentAttemptId);
	if (!attempt || attempt.id !== parsed.value.attemptId || !ATTEMPT_STATES.has(attempt.state) ||
		!DELIVERY_STATES.has(String(intent.deliveryState)) ||
		(attempt.state === 'created' && attempt.createTransmissionStarted === true)) return domainError('storage_unavailable');
	if (parsed.value.actionId !== attempt.id) return domainError('forbidden');
	if (attempt.state === 'requires_action' &&
		!isCurrentPaystackAction(attempt.nextAction, parsed.value.attemptId, parsed.value.actionId)) {
		return domainError('storage_unavailable');
	}

	if (attempt.state === 'created' && attempt.createTransmissionStarted === false) {
		if (!dependencies.provider) return domainError('provider_unavailable');
		const started = await createPaystackCheckout({
			siteId: parsed.value.siteId,
			intentId: parsed.value.intentId,
			attemptId: parsed.value.attemptId,
			callbackUrl: parsed.value.callbackUrl,
			siteOrigin: parsed.value.siteOrigin,
		}, {
			...dependencies.provider,
			pluginId: dependencies.pluginId,
			...(dependencies.now ? { now: dependencies.now } : {}),
		});
		if (started.kind === 'invalid') return domainError('validation_error');
		if (started.kind === 'conflict') return domainError('intent_conflict');
		if (started.kind === 'unavailable') return domainError('provider_unavailable');
	}

	let current: OwnedActionIntent = intent;
	let currentAttempt = attempt;
	if (attempt.state === 'created' && attempt.createTransmissionStarted === false) {
		try {
			const latest = await dependencies.intents.getVersioned(parsed.value.intentId);
			if (!latest || !isAdmissionIntentRecord(latest.value) || !isProviderIntentRecord(latest.value) || !latest.revision) {
				return domainError('storage_unavailable');
			}
			current = latest.value as unknown as OwnedActionIntent;
			const found = current.attempts.find((item) => item.id === current.currentAttemptId);
			if (current.identityHmac !== parsed.value.intentId || current.currentAttemptId !== parsed.value.attemptId ||
				current.state !== found?.state || !found || !ATTEMPT_STATES.has(found.state) ||
				!DELIVERY_STATES.has(String(current.deliveryState)) ||
				(found.state === 'created' && found.createTransmissionStarted === true)) return domainError('intent_conflict');
			currentAttempt = found;
		} catch {
			return domainError('storage_unavailable');
		}
	}
	if (currentAttempt.state === 'requires_action' &&
		!isCurrentPaystackAction(currentAttempt.nextAction, parsed.value.attemptId, parsed.value.actionId)) {
		return domainError('storage_unavailable');
	}

	return domainOk({
		schemaVersion: '1.0',
		intentId: parsed.value.intentId,
		attemptId: currentAttempt.id,
		state: currentAttempt.state,
		amount: { currency: 'NGN', value: snapshot.amount.value },
		deliveryState: current.deliveryState,
		stage: 'provider_work',
		...(currentAttempt.state === 'requires_action' && isCurrentPaystackAction(
			currentAttempt.nextAction, parsed.value.attemptId, parsed.value.actionId,
		) ? { nextAction: currentAttempt.nextAction } : {}),
	});
}

/** Read only an attested owner's persisted state; never infer success from a redirect. */
export async function handleSiteStatus(rawBody: unknown, request: SandboxedRequest, dependencies: SiteActionDependencies): Promise<unknown> {
	const authenticated = await authenticatePaymentRoute('payments/status', rawBody, request, dependencies);
	if (!authenticated.ok) return authenticated;
	const { runtime, body, siteId } = authenticated.value;
	if (!isPlainObject(body) || !hasExactKeys(body, ['schemaVersion', 'siteId', 'subject', 'merchantProfile', 'intentId'], ['attemptId'])) return domainError('validation_error');
	if (body.schemaVersion !== '1.0') return domainError('unsupported_schema');
	if (body.siteId !== siteId || !isSafeIdentifier(body.siteId) || !isPlainObject(body.subject) ||
		!hasExactKeys(body.subject, ['kind', 'id']) || (body.subject.kind !== 'member' && body.subject.kind !== 'guest') ||
		!isSafeIdentifier(body.subject.id) || !isSafeIdentifier(body.merchantProfile) || typeof body.intentId !== 'string' ||
		!INTENT_ID.test(body.intentId) || (body.attemptId !== undefined && (typeof body.attemptId !== 'string' || !ATTEMPT_ID.test(body.attemptId)))) return domainError('validation_error');
	const owned = await readOwnedIntent({
		siteId: body.siteId, merchantProfile: body.merchantProfile, intentId: body.intentId,
		subject: { kind: body.subject.kind, id: body.subject.id },
	}, runtime, dependencies);
	if (!owned.ok) return owned;
	const { intent, snapshot, record } = owned.value;
	const current = intent.attempts.find((item) => item.id === intent.currentAttemptId);
	const requested = body.attemptId ?? intent.currentAttemptId;
	const attempt = intent.attempts.find((item) => item.id === requested);
	if (!attempt || !current) return domainError('forbidden');
	if (!DELIVERY_STATES.has(intent.deliveryState)) return domainError('storage_unavailable');
	const paid = intent.state === 'verified_paid';
	if (paid && (!isConsistentPaidAggregate(record) || !isPlainObject(record.resultEvent) ||
		!isPlainObject(record.resultEvent.amount) || record.resultEvent.amount.currency !== snapshot.amount.currency ||
		record.resultEvent.amount.value !== snapshot.amount.value)) return domainError('storage_unavailable');

	let state: string;
	if (paid && isPlainObject(record.resultEvent) && record.resultEvent.attemptId === attempt.id) {
		state = 'verified_paid';
	} else if (attempt.id !== current.id) {
		// Only a terminal historical attempt can be displayed. Its action must never be resumed.
		if (attempt.state !== 'verified_failed' && attempt.state !== 'verified_canceled') return domainError('forbidden');
		state = attempt.state;
	} else {
		if (paid || !ATTEMPT_STATES.has(intent.state) || intent.state !== attempt.state ||
			(attempt.state === 'created' && attempt.createTransmissionStarted === true)) return domainError('storage_unavailable');
		state = intent.state;
	}
	if (state === 'requires_action' && !isCurrentPaystackAction(attempt.nextAction, attempt.id, attempt.id)) return domainError('storage_unavailable');
	return domainOk({ schemaVersion: '1.0', intentId: body.intentId, attemptId: attempt.id, state,
		amount: { currency: 'NGN', value: snapshot.amount.value },
		deliveryState: state === 'verified_paid' ? intent.deliveryState : 'not_eligible',
		stage: state === 'verified_paid' || state === 'verified_failed' || state === 'verified_canceled' ? 'complete' : 'provider_work',
		...(state === 'requires_action' ? { nextAction: attempt.nextAction } : {}) });
}

async function readOwnedIntent(
	owner: Pick<TrustedActionRequest, 'intentId' | 'siteId' | 'merchantProfile' | 'subject'>,
	runtime: ConfigurationRuntime,
	dependencies: SiteActionDependencies,
) {
	const { intentId, siteId, merchantProfile, subject } = owner;
	let stored;
	try { stored = await dependencies.intents.getVersioned(intentId); } catch { return domainError('storage_unavailable'); }
	if (!stored) return domainError('forbidden');
	const record = stored.value;
	if (!stored.revision || !isAdmissionIntentRecord(record) || !isProviderIntentRecord(record)) return domainError('storage_unavailable');
	const intent = record as unknown as OwnedActionIntent;
	const snapshot = await decryptIntentSnapshot(runtime, dependencies.pluginId, record, intentId);
	if (!snapshot) return domainError('storage_unavailable');
	if (intent.identityHmac !== intentId || intent.siteId !== siteId || intent.merchantId !== merchantProfile ||
		intent.merchantProfile !== merchantProfile || snapshot.siteId !== siteId || snapshot.merchantProfile !== merchantProfile ||
		snapshot.subject.kind !== subject.kind || snapshot.subject.id !== subject.id ||
		snapshot.environment !== intent.environment || snapshot.credentialVersion !== intent.credentialVersion) return domainError('forbidden');
	return domainOk({ intent, snapshot, record });
}

export function parseTrustedActionRequest(
	input: unknown,
	attestedSiteId: string,
): { readonly ok: true; readonly value: TrustedActionRequest } | { readonly ok: false; readonly code: 'validation_error' | 'unsupported_schema' } {
	if (!isPlainObject(input) || !hasExactKeys(input,
		['schemaVersion', 'siteId', 'subject', 'merchantProfile', 'intentId', 'attemptId', 'actionId', 'siteOrigin', 'callbackUrl'], ['expectedEnvironment'])) {
		return { ok: false, code: 'validation_error' };
	}
	if (input.schemaVersion !== '1.0') return { ok: false, code: 'unsupported_schema' };
	if (input.siteId !== attestedSiteId || !isSafeIdentifier(input.siteId) || !isPlainObject(input.subject) ||
		!hasExactKeys(input.subject, ['kind', 'id']) || (input.subject.kind !== 'guest' && input.subject.kind !== 'member') ||
		!isSafeIdentifier(input.subject.id) || !isSafeIdentifier(input.merchantProfile) ||
		typeof input.intentId !== 'string' || !INTENT_ID.test(input.intentId) ||
		typeof input.attemptId !== 'string' || !ATTEMPT_ID.test(input.attemptId) ||
		typeof input.actionId !== 'string' || !ATTEMPT_ID.test(input.actionId) ||
		(input.expectedEnvironment !== undefined && input.expectedEnvironment !== 'test' && input.expectedEnvironment !== 'live') ||
		typeof input.siteOrigin !== 'string' || typeof input.callbackUrl !== 'string' ||
		!isHttpsSameSiteCallback(input.callbackUrl, input.siteOrigin)) return { ok: false, code: 'validation_error' };
	return {
		ok: true,
		value: {
			schemaVersion: '1.0', siteId: input.siteId,
			subject: input.subject as TrustedActionRequest['subject'],
			merchantProfile: input.merchantProfile, intentId: input.intentId,
			attemptId: input.attemptId, actionId: input.actionId,
			siteOrigin: input.siteOrigin, callbackUrl: input.callbackUrl,
			...(input.expectedEnvironment !== undefined ? { expectedEnvironment: input.expectedEnvironment as 'test' | 'live' } : {}),
		},
	};
}

function isCurrentPaystackAction(value: unknown, attemptId: string, actionId: string): value is ProviderNextAction {
	if (!isPlainObject(value) || !hasExactKeys(value, ['id', 'kind', 'destination']) ||
		!isProviderNextAction(value) || value.id !== attemptId || value.id !== actionId) return false;
	return parsePaystackCheckoutUrl(value.destination) === value.destination;
}


function isSafeIdentifier(value: unknown): value is string {
	return typeof value === 'string' && IDENTIFIER.test(value) && !/[\u0000-\u001f\u007f]/u.test(value);
}

/** Provider/source aliases remain inside the existing finite safe error vocabulary. */
export function safeActionErrorCode(value: unknown): SafeErrorCode {
	return isSafeErrorCode(value) ? value : mapSafeErrorCode(value);
}
