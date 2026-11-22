import { pluginResponse, type PluginContext, type SandboxedRouteContext } from 'emdash/plugin';
import {
	PAYMENT_CONFIGURATION_SETTING,
	MAX_CREDENTIAL_VERSIONS_PER_PROFILE,
	parsePaymentConfigurationSetting,
	type CredentialVersion,
	type SettingsPort,
} from '../domain/configuration.js';
import { hmacIndex, createIndexHmacKey, decodeBase64Url, toHex, type IndexHmacKey } from '../security/encryption.js';
import { LosslessJsonNumber, parseStrictJson } from '../security/json.js';
import { meterCollection, StageBudget } from '../security/limits.js';
import { parsePaystackReference } from '../provider/paystack-reference.js';
import { isAdmissionIntentRecord } from '../storage/admission.js';
import {
	acceptWebhookInbox,
	MAX_WEBHOOK_INBOX_RECORD_BYTES,
	WEBHOOK_INBOX_RETENTION_MS,
	type WebhookInboxRecord,
} from '../storage/inbox.js';
import { isProviderIntentRecord } from '../storage/provider-work.js';
import { isPlainObject, type ModelRecord, type VersionedCollection } from '../storage/schema.js';

export const MAX_PAYSTACK_WEBHOOK_BYTES = 256 * 1024;
export const MAX_WEBHOOK_CREDENTIAL_VERSIONS = MAX_CREDENTIAL_VERSIONS_PER_PROFILE;
const EVENT_TYPE = /^[a-z][a-z0-9_.-]{0,63}$/u;
const REFERENCE = /^[A-Za-z0-9.=\-]{1,100}$/u;
const PROFILE_ID = /^[A-Za-z0-9_-]{1,120}$/u;
const RESOURCE_ID = /^[0-9]{1,24}$/u;

export interface PaystackWebhookDependencies {
	readonly settings: Pick<SettingsPort, 'getVersioned'>;
	readonly inbox: Pick<VersionedCollection<ModelRecord>, 'getVersioned' | 'compareAndSet'>;
	readonly intents: Pick<VersionedCollection<ModelRecord>, 'getVersioned'>;
	readonly now?: () => number;
	readonly crypto?: Crypto;
}

export interface PaystackWebhookResult {
	readonly status: 200 | 400 | 401 | 413 | 429 | 503;
	readonly body: 'accepted' | 'invalid request' | 'invalid signature' | 'too large' | 'rate limited' | 'unavailable';
}

interface EventCorrelation {
	readonly eventType: string;
	readonly reference: string;
	readonly providerResourceId: string | null;
}

/** Authenticate original Paystack bytes, then durably admit only bounded event correlation. */
export async function handlePaystackWebhook(
	rawBody: unknown,
	request: Pick<SandboxedRouteContext['request'], 'method' | 'url' | 'headers'>,
	dependencies: PaystackWebhookDependencies,
): Promise<PaystackWebhookResult> {
	if (request.method !== 'POST') return result(400, 'invalid request');
	if (!(rawBody instanceof Uint8Array)) return result(400, 'invalid request');
	if (rawBody.byteLength > MAX_PAYSTACK_WEBHOOK_BYTES) return result(413, 'too large');
	const signatureHex = request.headers['x-paystack-signature'];
	if (typeof signatureHex !== 'string' || !/^[a-f0-9]{128}$/u.test(signatureHex)) return result(401, 'invalid signature');
	if (!isWebhookRouteUrl(request.url)) return result(401, 'invalid signature');

	let persisted: { readonly value: unknown; readonly revision: string } | null;
	try { persisted = await dependencies.settings.getVersioned<unknown>(PAYMENT_CONFIGURATION_SETTING); }
	catch { return result(503, 'unavailable'); }
	const configuration = parsePaymentConfigurationSetting(persisted?.value);
	if (!configuration?.activeProfile || !PROFILE_ID.test(configuration.activeProfile)) return result(401, 'invalid signature');
	const profile = configuration.profiles[configuration.activeProfile];
	if (!profile || profile.profileId !== configuration.activeProfile || profile.credentialVersions.length < 1) {
		return result(401, 'invalid signature');
	}
	if (profile.credentialVersions.length > MAX_WEBHOOK_CREDENTIAL_VERSIONS) return result(503, 'unavailable');

	const cryptoProvider = dependencies.crypto ?? globalThis.crypto;
	const signature = fromHex(signatureHex);
	const matching = await matchingCredentials(rawBody, signature, profile.credentialVersions, cryptoProvider);
	if (matching.kind === 'error') return result(503, 'unavailable');
	if (matching.kind === 'invalid') return result(401, 'invalid signature');

	let event: EventCorrelation | null;
	try {
		const parsed = parseStrictJson(rawBody, MAX_PAYSTACK_WEBHOOK_BYTES, { numericMode: 'lossless' });
		event = parseEventCorrelation(parsed);
	} catch {
		return result(400, 'invalid request');
	}
	if (!event) return result(400, 'invalid request');
	const linked = await findLinkedAttempt(dependencies.intents, configuration.activeProfile,
		matching.value.environment, matching.value.versions, event.reference);
	if (linked === 'unavailable') return result(503, 'unavailable');
	const credentialVersion = linked?.credentialVersion ?? matching.value.versions[0]!.version;

	const nowMs = dependencies.now?.() ?? Date.now();
	if (!Number.isSafeInteger(nowMs) || nowMs < 0) return result(503, 'unavailable');
	try {
		const activeIdentity = configuration.identityHmacKeyRing.keys.find((item) => item.keyId === configuration.identityHmacKeyRing.activeKeyId);
		if (!activeIdentity) return result(503, 'unavailable');
		const identityKey = createIndexHmacKey(activeIdentity.keyId, decodeBase64Url(activeIdentity.material));
		const semanticKey = await deriveSemanticKey(configuration.activeProfile, matching.value.environment, event, identityKey, cryptoProvider);
		const payloadDigest = await digestSha256(rawBody, cryptoProvider);
		const acceptedAt = new Date(nowMs).toISOString();
		const purgeAt = nowMs + WEBHOOK_INBOX_RETENTION_MS;
		if (!Number.isSafeInteger(purgeAt) || !Number.isFinite(Date.parse(acceptedAt))) return result(503, 'unavailable');
		const record: WebhookInboxRecord = Object.freeze({
			modelVersion: 1,
			semanticKey,
			payloadDigest,
			profileId: configuration.activeProfile,
			environment: matching.value.environment,
			credentialVersion,
			eventType: event.eventType,
			reference: event.reference,
			providerResourceId: event.providerResourceId,
			intentId: linked?.intentId ?? null,
			attemptId: linked?.attemptId ?? null,
			state: 'accepted',
			dueAt: nowMs,
			leaseEpoch: 0,
			acceptedAt,
			purgeAt,
		});
		if (new TextEncoder().encode(JSON.stringify(record)).byteLength > MAX_WEBHOOK_INBOX_RECORD_BYTES) return result(400, 'invalid request');
		const accepted = await acceptWebhookInbox(dependencies.inbox, record);
		return accepted.kind === 'durable' ? result(200, 'accepted') : result(503, 'unavailable');
	} catch { return result(503, 'unavailable'); }
}

/** The sandbox route exposes one exact active profile and spends no provider HTTP capability. */
export async function paystackWebhookRoute(routeCtx: SandboxedRouteContext, ctx: PluginContext) {
	const budget = new StageBudget('webhook', () => Date.now());
	const settings: PaystackWebhookDependencies['settings'] = {
		getVersioned: <T>(key: string) => budget.run('settings', 'settings.read', () => ctx.settings.getVersioned<T>(key)),
	};
	const storage = ctx.storage.inbox as unknown as VersionedCollection<ModelRecord>;
	const intents = ctx.storage.intents as unknown as VersionedCollection<ModelRecord>;
	const inbox = meterCollection(storage, budget);
	const intentCollection = meterCollection(intents, budget);
	let accepted: PaystackWebhookResult;
	try {
		accepted = await handlePaystackWebhook(routeCtx.input, routeCtx.request, { settings, inbox, intents: intentCollection });
	} catch {
		accepted = result(503, 'unavailable');
	}
	return pluginResponse({
		status: accepted.status,
		headers: { 'content-type': 'text/plain; charset=utf-8' },
		body: { kind: 'text', value: accepted.body },
	});
}

async function findLinkedAttempt(
	intents: PaystackWebhookDependencies['intents'],
	profileId: string,
	environment: 'test' | 'live',
	credentialVersions: readonly CredentialVersion[],
	reference: string,
): Promise<{ readonly intentId: string; readonly attemptId: string; readonly credentialVersion: number } | null | 'unavailable'> {
	const identity = parsePaystackReference(reference);
	if (!identity) return null;
	let stored: { readonly value: ModelRecord; readonly revision: string } | null;
	try { stored = await intents.getVersioned(identity.intentId); } catch { return 'unavailable'; }
	if (!stored || !isAdmissionIntentRecord(stored.value) || !isProviderIntentRecord(stored.value) ||
		stored.value.identityHmac !== identity.intentId || stored.value.merchantProfile !== profileId ||
		stored.value.environment !== environment) return null;
	const attempt = stored.value.attempts.find((candidate) => candidate.ordinal === identity.attemptOrdinal &&
		candidate.providerReference === reference && candidate.createTransmissionStarted &&
		credentialVersions.some((version) => version.version === candidate.credentialVersion));
	return attempt ? { intentId: identity.intentId, attemptId: attempt.id, credentialVersion: attempt.credentialVersion } : null;
}

async function matchingCredentials(
	rawBody: Uint8Array,
	signature: Uint8Array,
	versions: readonly CredentialVersion[],
	cryptoProvider: Crypto,
): Promise<{ readonly kind: 'matched'; readonly value: { readonly environment: 'test' | 'live'; readonly versions: readonly CredentialVersion[] } } | { readonly kind: 'invalid' } | { readonly kind: 'error' }> {
	let matches: CredentialVersion[] = [];
	try {
		for (const candidate of versions) {
			const key = await cryptoProvider.subtle.importKey('raw', toArrayBuffer(new TextEncoder().encode(candidate.secretKey)),
				{ name: 'HMAC', hash: 'SHA-512' }, false, ['verify']);
			if (await cryptoProvider.subtle.verify('HMAC', key, toArrayBuffer(signature), toArrayBuffer(rawBody))) matches.push(candidate);
		}
	} catch { return { kind: 'error' }; }
	if (matches.length === 0) return { kind: 'invalid' };
	const environments = new Set(matches.map((candidate) => candidate.environment));
	if (environments.size !== 1) return { kind: 'invalid' };
	matches = matches.sort((left, right) => right.version - left.version);
	// Reused secret values can match retained historical versions. Keep the bounded set until
	// the exact persisted attempt reference selects its immutable credential version.
	return { kind: 'matched', value: Object.freeze({ environment: matches[0]!.environment, versions: Object.freeze(matches) }) };
}

function parseEventCorrelation(value: unknown): EventCorrelation | null {
	if (!isPlainObject(value) || typeof value.event !== 'string' || !EVENT_TYPE.test(value.event) || !isPlainObject(value.data)) return null;
	const reference = value.data.reference;
	if (typeof reference !== 'string' || !REFERENCE.test(reference)) return null;
	const providerResourceId = parseResourceId(value.data.id);
	return Object.freeze({ eventType: value.event, reference, providerResourceId });
}

function parseResourceId(value: unknown): string | null {
	if (typeof value === 'string') return RESOURCE_ID.test(value) ? value : null;
	if (value instanceof LosslessJsonNumber) return RESOURCE_ID.test(value.lexeme) ? value.lexeme : null;
	if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) return String(value);
	return null;
}

async function deriveSemanticKey(
	profileId: string,
	environment: 'test' | 'live',
	event: EventCorrelation,
	key: IndexHmacKey,
	cryptoProvider: Crypto,
): Promise<string> {
	return hmacIndex(['paystack-webhook-v1', profileId, environment, event.eventType, event.reference], key, cryptoProvider);
}

async function digestSha256(bytes: Uint8Array, cryptoProvider: Crypto): Promise<string> {
	const digest = await cryptoProvider.subtle.digest('SHA-256', toArrayBuffer(bytes));
	return toHex(new Uint8Array(digest));
}

function isWebhookRouteUrl(urlValue: string): boolean {
	try {
		const url = new URL(urlValue);
		return (url.protocol === 'https:' || url.protocol === 'http:') &&
			url.pathname.endsWith('/provider/webhook') && !url.username && !url.password && !url.hash;
	} catch { return false; }
}

function fromHex(value: string): Uint8Array {
	const bytes = new Uint8Array(value.length / 2);
	for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
	return bytes;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function result(status: PaystackWebhookResult['status'], body: PaystackWebhookResult['body']): PaystackWebhookResult {
	return Object.freeze({ status, body });
}
