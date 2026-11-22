import type { PluginContext } from 'emdash/plugin';
import {
	readPaymentConfiguration,
	type SettingsPort,
} from '../domain/configuration.js';
import { getExpectedPayment, readPaymentSnapshot } from '../domain/payment-snapshot.js';
import { cancelBody, readBoundedBody } from '../security/http-body.js';
import { createPaystackReference } from './paystack-reference.js';
import { readFieldEncryptionKeys } from '../security/encryption.js';
import { parseStrictJson } from '../security/json.js';
import { meterCollection, meterSettings,
	StageBudget,
	StageBudgetExceeded,
	waitForProvider,
	type ProviderWaitResult,
} from '../security/limits.js';
import { deterministicRecordId, isPlainObject, type ModelRecord, type VersionedCollection } from '../storage/schema.js';
import {
	markProviderCreateStarted,
	persistProviderCreateObservation,
	reserveProviderQuota,
	releaseProviderQuota,
	isProviderIntentRecord,
	isProviderNextAction,
	type ProviderCreateObservation,
	type ProviderNextAction,
} from '../storage/provider-work.js';

export const PAYSTACK_INITIALIZE_URL = 'https://api.paystack.co/transaction/initialize';
export const MAX_PAYSTACK_RESPONSE_BYTES = 256 * 1024;
const MAX_PAYSTACK_REQUEST_BYTES = 64 * 1024;
const MAX_CALLBACK_URL_LENGTH = 2_048;

export interface PaystackCreateRequest {
	readonly siteId: string;
	readonly intentId: string;
	readonly attemptId: string;
	/** A site-server-resolved HTTPS callback URL, never a browser destination. */
	readonly callbackUrl: string;
	/** Exact origin belonging to the consuming site; the callback must stay on it. */
	readonly siteOrigin: string;
}

export interface PaystackCreateDependencies {
	readonly pluginId: string;
	readonly settings: SettingsPort;
	readonly intents: VersionedCollection<ModelRecord>;
	readonly budgets: VersionedCollection<ModelRecord>;
	readonly fetch: (url: string, init?: RequestInit) => Promise<Response>;
	readonly now?: () => number;
	readonly randomBytes?: (length: number) => Uint8Array;
	readonly crypto?: Crypto;
}

export type PaystackCreateResult =
	| { readonly kind: 'next_action'; readonly intentId: string; readonly attemptId: string; readonly nextAction: ProviderNextAction }
	| { readonly kind: 'pending'; readonly intentId: string; readonly attemptId: string }
	| { readonly kind: 'conflict' | 'invalid' | 'unavailable' };

interface PaystackPayload {
	readonly email: string;
	readonly amount: string;
	readonly currency: 'NGN';
	readonly reference: string;
	readonly callback_url: string;
	readonly channels: readonly ['card'];
}

interface InitializationResponse {
	readonly kind: 'valid';
	readonly nextAction: ProviderNextAction;
}

type InitializationResponseResult = InitializationResponse | { readonly kind: 'invalid' };

/**
 * Create exactly one hosted-card transaction for the current owned attempt.
 * The site handler must authenticate/authorize this request and resolve its callback URL first.
 */
export async function createPaystackCheckout(
	input: PaystackCreateRequest,
	dependencies: PaystackCreateDependencies,
): Promise<PaystackCreateResult> {
	const now = dependencies.now ?? Date.now;
	let budget: StageBudget;
	try {
		budget = new StageBudget('provider', now);
	} catch {
		return { kind: 'unavailable' };
	}
	const settings = meterSettings(dependencies.settings, budget);
	const intents = meterCollection(dependencies.intents, budget);
	const budgets = meterCollection(dependencies.budgets, budget);

	try {
		if (!isCreateRequest(input) || !dependencies.pluginId || !isHttpsSameSiteCallback(input.callbackUrl, input.siteOrigin)) {
			return { kind: 'invalid' };
		}
		const nowMs = now();
		if (!Number.isSafeInteger(nowMs) || nowMs < 0) return { kind: 'unavailable' };
		const configuration = await readPaymentConfiguration(settings);
		if (!configuration || configuration.paused) return { kind: 'unavailable' };
		const versioned = await intents.getVersioned(input.intentId);
		if (!versioned || !isProviderIntentRecord(versioned.value) || !versioned.revision) return { kind: 'unavailable' };
		const intent = versioned.value;
		if (intent.siteId !== input.siteId || intent.identityHmac !== input.intentId) return { kind: 'conflict' };
		if (intent.currentAttemptId !== input.attemptId) return { kind: 'conflict' };
		const currentAttempt = intent.attempts.find((attempt) => attempt.id === input.attemptId);
		if (!currentAttempt) return { kind: 'unavailable' };
		if (currentAttempt.createTransmissionStarted) {
			return currentAttempt.state === 'requires_action' && isSafePaystackNextAction(currentAttempt.nextAction, input.attemptId)
				? { kind: 'next_action', intentId: input.intentId, attemptId: input.attemptId, nextAction: currentAttempt.nextAction }
				: { kind: 'pending', intentId: input.intentId, attemptId: input.attemptId };
		}
		if (intent.state !== 'created' || currentAttempt.state !== 'created' || currentAttempt.providerState !== 'not_started' ||
			currentAttempt.providerReference !== null || currentAttempt.credentialVersion !== intent.credentialVersion) {
			return { kind: 'conflict' };
		}
		const profile = configuration.profiles[intent.merchantProfile];
		const credential = profile?.credentialVersions.find((candidate) => candidate.version === intent.credentialVersion);
		if (!profile || profile.profileId !== intent.merchantProfile || !credential || credential.environment !== intent.environment) {
			return { kind: 'unavailable' };
		}
		const encryptionKeys = readFieldEncryptionKeys(configuration.fieldEncryptionKeyRing.keys);
		if (!encryptionKeys) return { kind: 'unavailable' };
		const snapshot = await readPaymentSnapshot(dependencies.pluginId, 'intents', input.intentId, intent.protectedSnapshot, encryptionKeys);
		if (!snapshot || snapshot.siteId !== input.siteId || snapshot.merchantProfile !== intent.merchantProfile ||
			snapshot.environment !== intent.environment || snapshot.credentialVersion !== intent.credentialVersion) return { kind: 'unavailable' };
		const validated = getExpectedPayment(snapshot);
		if (!validated) return { kind: 'invalid' };
		const workerBytes = getRandomBytes(dependencies, 16);
		const reference = createPaystackReference(input.intentId, currentAttempt.ordinal);
		if (!reference || !workerBytes) return { kind: 'unavailable' };
		const workerId = toHex(workerBytes);
		const payload: PaystackPayload = Object.freeze({
			email: validated.email,
			amount: String(validated.amountMinor),
			currency: 'NGN',
			reference,
			callback_url: input.callbackUrl,
			channels: Object.freeze(['card']) as readonly ['card'],
		});
		const payloadText = JSON.stringify(payload);
		const payloadBytes = new TextEncoder().encode(payloadText);
		if (payloadBytes.byteLength > MAX_PAYSTACK_REQUEST_BYTES) return { kind: 'invalid' };
		const payloadDigest = await digestSha256(payloadBytes, dependencies.crypto ?? globalThis.crypto);
		if (!payloadDigest) return { kind: 'unavailable' };
		const quotaNowMs = now();
		if (!Number.isSafeInteger(quotaNowMs) || quotaNowMs < 0 || !Number.isFinite(new Date(quotaNowMs).getTime())) {
			return { kind: 'unavailable' };
		}
		const quotaScopeDigest = await digestSha256(
			new TextEncoder().encode(`${intent.merchantProfile}\n${intent.environment}\ntransaction_initialize`),
			dependencies.crypto ?? globalThis.crypto,
		);
		if (!quotaScopeDigest) return { kind: 'unavailable' };
		const quotaId = deterministicRecordId('budgets', quotaScopeDigest);
		const quota = await reserveProviderQuota(
			budgets,
			quotaId,
			quotaScopeDigest,
			workerId,
			input.attemptId,
			reference,
			intent.environment === 'test' ? 10 : 30,
			quotaNowMs,
		);
		if (quota.kind !== 'reserved') {
			return quota.kind === 'invalid'
				? { kind: 'unavailable' }
				: { kind: 'pending', intentId: input.intentId, attemptId: input.attemptId };
		}
		const startedAt = new Date(quotaNowMs).toISOString();
		const marked = await markProviderCreateStarted(intents, input.intentId, versioned.revision, intent, {
			attemptId: input.attemptId,
			workerId,
			reference,
			payloadDigest,
			credentialVersion: credential.version,
			startedAt,
			nowMs: quotaNowMs,
		});
		if (marked.kind === 'already_started') {
			await releaseProviderQuota(budgets, quotaId, quota.revision, quota.record, quota.lease);
			return marked.attempt.state === 'requires_action' && isSafePaystackNextAction(marked.attempt.nextAction, input.attemptId)
				? { kind: 'next_action', intentId: input.intentId, attemptId: input.attemptId, nextAction: marked.attempt.nextAction }
				: { kind: 'pending', intentId: input.intentId, attemptId: input.attemptId };
		}
		if (marked.kind !== 'marked') {
			await releaseProviderQuota(budgets, quotaId, quota.revision, quota.record, quota.lease);
			return marked.kind === 'invalid' ? { kind: 'invalid' } : { kind: 'pending', intentId: input.intentId, attemptId: input.attemptId };
		}
		const responseWait = await budget.run('http', 'http.fetch', () =>
			fetchWithLocalDeadline(dependencies.fetch, credential.secretKey, payloadText, reference, input.attemptId));
		const parsed = responseWait.kind === 'completed'
			? responseWait.value
			: { kind: 'invalid' as const };
		const observedMs = now();
		if (!Number.isSafeInteger(observedMs) || observedMs < 0 || !Number.isFinite(new Date(observedMs).getTime())) {
			return { kind: 'pending', intentId: input.intentId, attemptId: input.attemptId };
		}
		const observedAt = new Date(observedMs).toISOString();
		const observation: ProviderCreateObservation = parsed.kind === 'valid'
			? { kind: 'requires_action', nextAction: parsed.nextAction, observedAt }
			: { kind: 'unknown', nextRunAt: observedMs + 60_000, observedAt };
		const persisted = await persistProviderCreateObservation(
			intents, input.intentId, marked.revision, marked.record, marked.lease, observation,
		);
		// A local timeout does not cancel the sandbox HTTP request. Leave the concurrency
		// lease to expire naturally while the provider outcome remains uncertain.
		if (responseWait.kind !== 'wait_expired') {
			await releaseProviderQuota(budgets, quotaId, quota.revision, quota.record, quota.lease);
		}
		if (persisted.kind !== 'written') return { kind: 'pending', intentId: input.intentId, attemptId: input.attemptId };
		if (observation.kind === 'requires_action') {
			return { kind: 'next_action', intentId: input.intentId, attemptId: input.attemptId, nextAction: observation.nextAction };
		}
		return { kind: 'pending', intentId: input.intentId, attemptId: input.attemptId };
	} catch (error) {
		if (error instanceof StageBudgetExceeded) {
			return { kind: 'pending', intentId: safeIdentifier(input?.intentId), attemptId: safeIdentifier(input?.attemptId) };
		}
		return { kind: 'unavailable' };
	}
}

/** Construct the worker dependencies from the installed EmDash sandbox context. */
export function createPaystackCheckoutFromContext(input: PaystackCreateRequest, ctx: PluginContext): Promise<PaystackCreateResult> {
	if (!ctx.http) return Promise.resolve({ kind: 'unavailable' });
	const intents = ctx.storage.intents as unknown as VersionedCollection<ModelRecord>;
	const budgets = ctx.storage.budgets as unknown as VersionedCollection<ModelRecord>;
	const settings: SettingsPort = {
		getVersioned: <T>(key: string) => ctx.settings.getVersioned<T>(key),
		compareAndSet: (key, expectedRevision, value) => ctx.settings.compareAndSet(key, expectedRevision, value),
	};
	return createPaystackCheckout(input, {
		pluginId: ctx.plugin.id,
		settings,
		intents,
		budgets,
		fetch: (url, init) => ctx.http!.fetch(url, init),
	});
}

/** Bounded strict parser; numeric provider tokens remain exact LosslessJsonNumber values. */
export function parsePaystackJson(text: string): unknown {
	return parseStrictJson(new TextEncoder().encode(text), MAX_PAYSTACK_RESPONSE_BYTES, { numericMode: 'lossless' });
}

export async function parsePaystackInitializationResponse(
	response: Response,
	expectedReference: string,
	attemptId: string,
): Promise<InitializationResponseResult> {
	if (response.status !== 200 || response.redirected || response.type === 'opaqueredirect' ||
		(response.url !== '' && !isPaystackApiUrl(response.url))) {
		await cancelBody(response);
		return { kind: 'invalid' };
	}
	const contentType = response.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
	if (contentType !== 'application/json') {
		await cancelBody(response);
		return { kind: 'invalid' };
	}
	const lengthHeader = response.headers.get('content-length');
	if (lengthHeader !== null && (!/^(?:0|[1-9][0-9]*)$/u.test(lengthHeader) || Number(lengthHeader) > MAX_PAYSTACK_RESPONSE_BYTES)) {
		await cancelBody(response);
		return { kind: 'invalid' };
	}
	const body = await readBoundedBody(response, MAX_PAYSTACK_RESPONSE_BYTES);
	if (!body) return { kind: 'invalid' };
	let parsed: unknown;
	try { parsed = parsePaystackJson(new TextDecoder('utf-8', { fatal: true }).decode(body)); } catch { return { kind: 'invalid' }; }
	if (!isPlainObject(parsed) || parsed.status !== true || !isPlainObject(parsed.data) ||
		parsed.data.reference !== expectedReference) return { kind: 'invalid' };
	const destination = parsePaystackCheckoutUrl(parsed.data.authorization_url);
	if (!destination) return { kind: 'invalid' };
	return {
		kind: 'valid',
		nextAction: Object.freeze({ id: attemptId, kind: 'redirect', destination }),
	};
}

export function parsePaystackCheckoutUrl(value: unknown): string | null {
	if (typeof value !== 'string' || value.length < 1 || value.length > 2_048) return null;
	try {
		const url = new URL(value);
		if (url.protocol !== 'https:' || url.hostname !== 'checkout.paystack.com' || url.port !== '' ||
			url.username !== '' || url.password !== '' || url.search !== '' || url.hash !== '' ||
			!/^\/[A-Za-z0-9._~-]{1,255}$/u.test(url.pathname)) return null;
		return url.toString();
	} catch { return null; }
}

function isSafePaystackNextAction(value: unknown, attemptId: string): value is ProviderNextAction {
	if (!isProviderNextAction(value) || value.id !== attemptId) return false;
	return parsePaystackCheckoutUrl(value.destination) === value.destination;
}


async function fetchWithLocalDeadline(
	fetch: (url: string, init?: RequestInit) => Promise<Response>,
	secretKey: string,
	body: string,
	expectedReference: string,
	attemptId: string,
): Promise<ProviderWaitResult<InitializationResponseResult>> {
	const request = Promise.resolve()
		.then(() => fetch(PAYSTACK_INITIALIZE_URL, {
			method: 'POST',
			headers: {
				accept: 'application/json',
				authorization: `Bearer ${secretKey}`,
				'content-type': 'application/json',
			},
			body,
			redirect: 'manual',
		}))
		.then((response) => parsePaystackInitializationResponse(response, expectedReference, attemptId));
	return waitForProvider(request);
}

function isCreateRequest(value: PaystackCreateRequest): boolean {
	return Boolean(value && isSafeIdentifier(value.siteId) && /^psk:v1:intents:[a-f0-9]{64}$/u.test(value.intentId) &&
		/^psk:v1:attempts:[a-f0-9]{64}$/u.test(value.attemptId) && typeof value.callbackUrl === 'string' &&
		typeof value.siteOrigin === 'string');
}

export function isHttpsSameSiteCallback(callbackUrl: string, siteOrigin: string): boolean {
	if (callbackUrl.length < 1 || callbackUrl.length > MAX_CALLBACK_URL_LENGTH || siteOrigin.length > 2_048) return false;
	try {
		const site = new URL(siteOrigin);
		const callback = new URL(callbackUrl);
		return site.protocol === 'https:' && site.origin === siteOrigin && site.username === '' && site.password === '' &&
			callback.protocol === 'https:' && callback.origin === site.origin && callback.username === '' && callback.password === '' &&
			callback.hash === '' && callback.search === '' && callback.pathname.startsWith('/') && callback.pathname.length <= 512;
	} catch { return false; }
}

function isPaystackApiUrl(value: string): boolean {
	try {
		const url = new URL(value);
		return url.protocol === 'https:' && url.hostname === 'api.paystack.co' && url.port === '' &&
			url.pathname === '/transaction/initialize' && url.username === '' && url.password === '';
	} catch { return false; }
}

function getRandomBytes(dependencies: PaystackCreateDependencies, length: number): Uint8Array | null {
	try {
		const bytes = dependencies.randomBytes?.(length) ?? (dependencies.crypto ?? globalThis.crypto).getRandomValues(new Uint8Array(length));
		return bytes instanceof Uint8Array && bytes.byteLength === length ? bytes : null;
	} catch { return null; }
}

async function digestSha256(bytes: Uint8Array, cryptoProvider: Crypto): Promise<string | null> {
	try {
		const exactBuffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
		return toHex(new Uint8Array(await cryptoProvider.subtle.digest('SHA-256', exactBuffer)));
	} catch { return null; }
}

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function safeIdentifier(value: unknown): string {
	return typeof value === 'string' && value.length <= 255 ? value : '';
}

function isSafeIdentifier(value: unknown): value is string {
	return typeof value === 'string' && /^[A-Za-z0-9_-]{1,120}$/u.test(value);
}
