import { withEmDashRuntime } from 'emdash/middleware';
import { safeError, type SafeErrorCode } from '../../../src/domain/errors.js';
import { fromRawHostExecution, toSiteHttpStatus, type DomainResult } from '../../../src/routes/response.js';
import { canonicalAttestationFrame } from '../../../src/security/attestation.js';
import { parseStrictJson } from '../../../src/security/json.js';
import {
	assignBusinessIntent,
	canSubmitIntent,
	DEFAULT_ADMISSION_ROLLOUT,
	isGuardedAdmissionRolloutState,
	identityKeyFingerprint,
	type AdmissionRolloutState,
} from './rollout.js';
import {
	authenticateSiteRequest,
	type PaymentSubject,
	type SiteAuthDependencies,
	type SitePaymentOperation,
} from './auth.js';
import type { PersistentPaymentStore } from './persistent-store.js';
import type { PersistentRateLimiter, SiteQuota } from './rate-limit.js';

const BODY_LIMIT_BYTES = 65_536;
const IDENTIFIER = /^[A-Za-z0-9_-]{1,255}$/u;
const INTENT_ID = /^psk:v1:intents:[a-f0-9]{64}$/u;
const ATTEMPT_ID = /^psk:v1:attempts:[a-f0-9]{64}$/u;
const FIELD_ID = /^[a-z][a-z0-9_]{0,63}$/u;
const METADATA_KEY = /^[a-z][a-z0-9_-]*\.[A-Za-z0-9_.-]+$/u;
const CANONICAL_AMOUNT = /^(?:[1-9][0-9]*(?:\.[0-9]+)?|0\.[0-9]*[1-9][0-9]*)$/u;
const OPERATION_ROUTES = Object.freeze({
	submit: 'payments/submit',
	action: 'payments/action',
	status: 'payments/status',
} satisfies Record<SitePaymentOperation, string>);

type PricingMode = 'fixed' | 'trusted_order' | 'payer_entered';

export interface TrustedSubmitContext {
	readonly merchantProfile: string;
	readonly businessReference: string;
	readonly publishedFormRevision: string;
	readonly pricingMode: PricingMode;
	readonly resolvedOrderPrice?: { readonly currency: 'NGN'; readonly value: string };
	/** True only when the site has resolved this exact business intent before. */
	readonly existingIntent: boolean;
}

export interface OwnedPaymentContext {
	readonly siteId: string;
	readonly subject: PaymentSubject;
	readonly intentId: string;
	readonly merchantProfile: string;
	readonly attemptId?: string;
	/** Current server-resolved action ID; the browser value is only a selector to compare. */
	readonly actionId?: string;
	/** Server-resolved same-site callback selected from the persisted form return policy. */
	readonly callbackUrl?: string;
}

export interface PaystackSiteAdapterOptions {
	/** Runtime-installed EmDash ID from site configuration; never derive this from the plugin slug. */
	readonly installedPluginId: string;
	readonly siteId: string;
	readonly keyId: string;
	/** Separate 32-byte site-attestation key. Server-only. */
	readonly siteAttestationKey: Uint8Array;
	/** Immutable 32-byte installation identity key. Never rotate for routine credential changes. */
	readonly identityHmacKey: Uint8Array;
	readonly auth?: SiteAuthDependencies;
	readonly store?: PersistentPaymentStore;
	readonly limiter?: PersistentRateLimiter;
	readonly rollout?: AdmissionRolloutState;
	readonly resolveSubmitContext: (input: {
		readonly principal: { readonly siteId: string; readonly subject: PaymentSubject };
		readonly submission: BrowserPaymentSubmission;
	}) => Promise<TrustedSubmitContext | null>;
	readonly resolveOwnedContext: (input: {
		readonly operation: 'action' | 'status';
		readonly principal: { readonly siteId: string; readonly subject: PaymentSubject };
		readonly intentId: string;
		readonly attemptId?: string;
		readonly actionId?: string;
	}) => Promise<OwnedPaymentContext | null>;
	readonly now?: () => number;
	readonly crypto?: Crypto;
}

export interface BrowserPaymentSubmission {
	readonly schemaVersion: '1.0';
	readonly formId: string;
	readonly formRevision: string;
	readonly requestKey: string;
	readonly fields: Readonly<Record<string, string | boolean>>;
	readonly payerAmount?: string;
	readonly metadata?: Readonly<Record<string, string | number | boolean | null>>;
}

export interface PaystackSiteAdapter {
	submit(request: Request): Promise<Response>;
	action(request: Request): Promise<Response>;
	status(request: Request): Promise<Response>;
	/** Call only after authenticating the configured result consumer on the site server. */
	consumeResultQuota(quota: 'feed' | 'ack', trustedConsumerId: string): Promise<boolean>;
	/** IP value must come from the consuming site's trusted edge adapter, never an arbitrary forwarded header. */
	consumePublicRenderQuota(trustedClientIp?: string): Promise<boolean>;
}

/**
 * Server-only site boundary. It accepts no caller-selected plugin/path, and all
 * browser-owned claims are rebuilt from the consuming site's authenticated
 * principal and order resolver before exact-byte signing.
 */
export function createPaystackSiteAdapter(options: PaystackSiteAdapterOptions): PaystackSiteAdapter {
	const now = options.now ?? Date.now;
	const cryptoProvider = options.crypto ?? globalThis.crypto;
	const rollout = isGuardedAdmissionRolloutState(options.rollout)
		? options.rollout
		: DEFAULT_ADMISSION_ROLLOUT;

	return Object.freeze({
		submit: (request: Request) => handleRequest(request, 'submit'),
		action: (request: Request) => handleRequest(request, 'action'),
		status: (request: Request) => handleRequest(request, 'status'),
		async consumeResultQuota(quota: 'feed' | 'ack', trustedConsumerId: string): Promise<boolean> {
			if (!isPersistentBoundaryConfigured(options) || !IDENTIFIER.test(trustedConsumerId)) return false;
			try {
				const nowMs = now();
				if (!(await bindIdentityKey(options, cryptoProvider))) return false;
				const sitePartition = await deriveDigest(options.identityHmacKey, ['rate-site', options.siteId], cryptoProvider);
				const consumerPartition = await deriveDigest(
					options.identityHmacKey,
					['rate-consumer', options.siteId, trustedConsumerId],
					cryptoProvider,
				);
				const result = await options.limiter!.consume({
					quota, sitePartition, subjectPartition: consumerPartition, nowMs,
				});
				return result.allowed;
			} catch {
				return false;
			}
		},
		async consumePublicRenderQuota(trustedClientIp?: string): Promise<boolean> {
			if (!isPersistentBoundaryConfigured(options) || !isAdapterConfigurationValid(options)) return false;
			try {
				const nowMs = now();
				if (!(await bindIdentityKey(options, cryptoProvider))) return false;
				const sitePartition = await deriveDigest(options.identityHmacKey, ['rate-site', options.siteId], cryptoProvider);
				if (trustedClientIp === undefined) {
					const result = await options.limiter!.consume({
						quota: 'public_render_site', sitePartition, subjectPartition: sitePartition, nowMs,
					});
					return result.allowed;
				}
				if (!/^[A-Fa-f0-9:.]{2,100}$/u.test(trustedClientIp)) return false;
				const ipPartition = await deriveDigest(options.identityHmacKey, ['rate-public-ip', trustedClientIp], cryptoProvider);
				const result = await options.limiter!.consume({
					quota: 'public_render_ip', sitePartition, subjectPartition: ipPartition, nowMs,
				});
				return result.allowed;
			} catch {
				return false;
			}
		},
	});

	async function handleRequest(request: Request, operation: SitePaymentOperation): Promise<Response> {
		if (!isPersistentBoundaryConfigured(options) || !isAdapterConfigurationValid(options)) {
			return errorResponse('storage_unavailable', 503);
		}
		const nowMs = now();
		const authentication = await authenticateSiteRequest(request, operation, options.siteId, options.auth, nowMs);
		if (!authentication.ok) {
			const code: SafeErrorCode = authentication.status === 405 ? 'unsupported_method' :
				authentication.status === 401 ? 'unauthorized' : 'forbidden';
			return errorResponse(code, authentication.status);
		}

		let body: unknown;
		try {
			body = await readStrictJson(request);
		} catch {
			return errorResponse('validation_error', 400);
		}

		const quota: SiteQuota = operation === 'status' ? 'status' : 'mutation';
		try {
			if (!(await bindIdentityKey(options, cryptoProvider))) return errorResponse('storage_unavailable', 503);
			const sitePartition = await deriveDigest(options.identityHmacKey, ['rate-site', options.siteId], cryptoProvider);
			const subjectPartition = await deriveDigest(
				options.identityHmacKey,
				['rate-subject', options.siteId, authentication.principal.subject.kind, authentication.principal.subject.id],
				cryptoProvider,
			);
			const quotaResult = await options.limiter!.consume({ quota, sitePartition, subjectPartition, nowMs });
			if (!quotaResult.allowed) return errorResponse('rate_limited', 429);
		} catch {
			return errorResponse('storage_unavailable', 503);
		}

		if (operation === 'submit') return handleSubmit(request, body, authentication.principal, nowMs);
		return handleOwned(request, body, operation, authentication.principal, nowMs);
	}

	async function handleSubmit(
		request: Request,
		input: unknown,
		principal: { readonly siteId: string; readonly subject: PaymentSubject },
		nowMs: number,
	): Promise<Response> {
		const submission = parseBrowserSubmission(input);
		if (!submission) return errorResponse('validation_error', 400);
		let context: TrustedSubmitContext | null;
		try {
			context = await options.resolveSubmitContext({ principal, submission });
		} catch {
			return errorResponse('provider_unavailable', 503);
		}
		if (!isTrustedSubmitContext(context, submission) || context.publishedFormRevision !== submission.formRevision) {
			return errorResponse('form_unavailable', 422);
		}

		try {
			const assignment = await assignBusinessIntent(options.identityHmacKey, {
				siteId: options.siteId,
				subject: principal.subject,
				businessReference: context.businessReference,
			}, cryptoProvider);
			const bucket = await options.store!.getOrCreateCohort(assignment.identityDigest, assignment.bucket);
			if (!canSubmitIntent(rollout, bucket, context.existingIntent)) {
				return errorResponse('review_required', 409);
			}
		} catch {
			return errorResponse('storage_unavailable', 503);
		}

		const trustedSubmission = {
			schemaVersion: '1.0',
			siteId: options.siteId,
			subject: principal.subject,
			businessReference: context.businessReference,
			merchantProfile: context.merchantProfile,
			submission,
			...(context.pricingMode === 'trusted_order' ? { resolvedOrderPrice: context.resolvedOrderPrice } : {}),
		};
		let response: Response | null = null;
		for (let stage = 0; stage < 3; stage += 1) {
			response = await invokeFixedRoute('submit', trustedSubmission, nowMs);
			if (response.status !== 202) return response;
			let payload: unknown;
			try { payload = await response.clone().json(); } catch { return response; }
			if (!isAdmissionPending(payload) || stage === 2) return response;
		}
		return response ?? errorResponse('provider_unavailable', 503);
	}

	async function handleOwned(
		request: Request,
		input: unknown,
		operation: 'action' | 'status',
		principal: { readonly siteId: string; readonly subject: PaymentSubject },
		nowMs: number,
	): Promise<Response> {
		if (operation === 'status') {
			const browserRequest = parseBrowserStatus(input);
			if (!browserRequest) return errorResponse('validation_error', 400);
			let context: OwnedPaymentContext | null;
			try {
				context = await options.resolveOwnedContext({ operation, principal, intentId: browserRequest.intentId,
					...(browserRequest.attemptId ? { attemptId: browserRequest.attemptId } : {}) });
			} catch {
				return errorResponse('provider_unavailable', 503);
			}
			if (!isOwnedPaymentContext(context, principal, options.siteId, browserRequest.intentId)) {
				return errorResponse('forbidden', 403);
			}
			if (browserRequest.attemptId && context.attemptId !== browserRequest.attemptId) return errorResponse('forbidden', 403);
			return invokeFixedRoute('status', {
				schemaVersion: '1.0', siteId: options.siteId, subject: principal.subject,
				merchantProfile: context.merchantProfile, intentId: context.intentId,
				...(browserRequest.attemptId ? { attemptId: context.attemptId } : {}),
			}, nowMs);
		}
		const browserRequest = parseBrowserAction(input);
		if (!browserRequest) return errorResponse('validation_error', 400);
		let context: OwnedPaymentContext | null;
		try {
			context = await options.resolveOwnedContext({ operation, principal, intentId: browserRequest.intentId,
				attemptId: browserRequest.attemptId, actionId: browserRequest.actionId });
		} catch {
			return errorResponse('provider_unavailable', 503);
		}
		if (!isOwnedPaymentContext(context, principal, options.siteId, browserRequest.intentId)) {
			return errorResponse('forbidden', 403);
		}
		if (context.attemptId !== browserRequest.attemptId || context.actionId !== browserRequest.actionId) {
			return errorResponse('forbidden', 403);
		}
		const siteOrigin = options.auth?.siteOrigin;
		if (!siteOrigin || !isSameSiteCallback(context.callbackUrl, siteOrigin)) {
			return errorResponse('provider_unavailable', 503);
		}
		return invokeFixedRoute('action', {
			schemaVersion: '1.0', siteId: options.siteId, subject: principal.subject,
			merchantProfile: context.merchantProfile, intentId: context.intentId,
			attemptId: context.attemptId, actionId: context.actionId,
			siteOrigin, callbackUrl: context.callbackUrl,
		}, nowMs);
	}

	async function invokeFixedRoute(
		operation: SitePaymentOperation,
		trustedBody: Readonly<Record<string, unknown>>,
		nowMs: number,
	): Promise<Response> {
		try {
			const rawBody = new TextEncoder().encode(JSON.stringify(trustedBody));
			const signedRequest = await signInternalRequest(rawBody, OPERATION_ROUTES[operation], nowMs, options, cryptoProvider);
			const raw = await withEmDashRuntime((runtime) => runtime.handlePluginApiRoute(
				options.installedPluginId,
				'POST',
				`/${OPERATION_ROUTES[operation]}`,
				signedRequest,
			));
			return domainResponse(fromRawHostExecution(raw));
		} catch {
			return errorResponse('provider_unavailable', 503);
		}
	}
}

async function signInternalRequest(
	body: Uint8Array,
	route: string,
	timestampMs: number,
	options: PaystackSiteAdapterOptions,
	cryptoProvider: Crypto,
): Promise<Request> {
	const timestampSeconds = Math.floor(timestampMs / 1000);
	const nonceBytes = new Uint8Array(24);
	cryptoProvider.getRandomValues(nonceBytes);
	const nonce = encodeBase64Url(nonceBytes);
	const bodyDigest = new Uint8Array(await cryptoProvider.subtle.digest('SHA-256', toArrayBuffer(body)));
	const frame = canonicalAttestationFrame({
		siteId: options.siteId,
		keyId: options.keyId,
		timestampSeconds,
		nonce,
		method: 'POST',
		route,
		bodyDigest: toHex(bodyDigest),
	});
	const key = await cryptoProvider.subtle.importKey('raw', toArrayBuffer(options.siteAttestationKey), {
		name: 'HMAC', hash: 'SHA-256',
	}, false, ['sign']);
	const signature = new Uint8Array(await cryptoProvider.subtle.sign(
		'HMAC', key, toArrayBuffer(new TextEncoder().encode(frame)),
	));
	const headers = new Headers({
		'content-type': 'application/json',
		'x-payment-site-id': options.siteId,
		'x-payment-key-id': options.keyId,
		'x-payment-timestamp': String(timestampSeconds),
		'x-payment-nonce': nonce,
		'x-payment-signature': toHex(signature),
	});
	return new Request(`https://emdash.internal/${route}`, { method: 'POST', headers, body: toArrayBuffer(body) });
}

async function readStrictJson(request: Request): Promise<unknown> {
	const mediaType = request.headers.get('content-type')?.split(';', 1)[0]?.trim().toLowerCase();
	if (mediaType !== 'application/json' || !request.body) throw new Error('JSON request body required');
	const reader = request.body.getReader();
	const chunks: Uint8Array[] = [];
	let length = 0;
	try {
		while (true) {
			const { done, value } = await reader.read();
			if (done) break;
			length += value.byteLength;
			if (length > BODY_LIMIT_BYTES) throw new Error('Body too large');
			chunks.push(value);
		}
	} finally {
		reader.releaseLock();
	}
	const bytes = new Uint8Array(length);
	let offset = 0;
	for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
	return parseStrictJson(bytes, BODY_LIMIT_BYTES);
}

function parseBrowserSubmission(value: unknown): BrowserPaymentSubmission | null {
	if (!isPlainObject(value) || !hasExactKeys(value,
		['schemaVersion', 'formId', 'formRevision', 'requestKey', 'fields'], ['payerAmount', 'metadata'])) return null;
	if (value.schemaVersion !== '1.0' || !isIdentifier(value.formId) || !isIdentifier(value.formRevision) ||
		!isIdentifier(value.requestKey) || !isScalarMap(value.fields, FIELD_ID, true) ||
		(Object.hasOwn(value, 'payerAmount') && !isCanonicalAmount(value.payerAmount)) ||
		(Object.hasOwn(value, 'metadata') && !isScalarMap(value.metadata, METADATA_KEY, false))) return null;
	return value as unknown as BrowserPaymentSubmission;
}

function parseBrowserStatus(value: unknown): { readonly intentId: string; readonly attemptId?: string } | null {
	if (!isPlainObject(value) || !hasExactKeys(value, ['schemaVersion', 'intentId'], ['attemptId']) ||
		value.schemaVersion !== '1.0' || !isIntentId(value.intentId) ||
		(Object.hasOwn(value, 'attemptId') && !isAttemptId(value.attemptId))) return null;
	return {
		intentId: value.intentId,
		...(typeof value.attemptId === 'string' ? { attemptId: value.attemptId } : {}),
	};
}

function parseBrowserAction(value: unknown): { readonly intentId: string; readonly attemptId: string; readonly actionId: string } | null {
	if (!isPlainObject(value) || !hasExactKeys(value, ['schemaVersion', 'intentId', 'attemptId', 'actionId']) ||
		value.schemaVersion !== '1.0' || !isIntentId(value.intentId) || !isAttemptId(value.attemptId) ||
		!isAttemptId(value.actionId)) return null;
	return { intentId: value.intentId, attemptId: value.attemptId, actionId: value.actionId };
}

function isTrustedSubmitContext(value: TrustedSubmitContext | null, submission: BrowserPaymentSubmission): value is TrustedSubmitContext {
	if (!value || !IDENTIFIER.test(value.merchantProfile) || !IDENTIFIER.test(value.businessReference) ||
		!IDENTIFIER.test(value.publishedFormRevision) || typeof value.existingIntent !== 'boolean') return false;
	if (value.pricingMode === 'fixed') return !Object.hasOwn(submission, 'payerAmount') && !value.resolvedOrderPrice;
	if (value.pricingMode === 'payer_entered') return isCanonicalAmount(submission.payerAmount) && !value.resolvedOrderPrice;
	if (value.pricingMode === 'trusted_order') return !Object.hasOwn(submission, 'payerAmount') && isMoney(value.resolvedOrderPrice);
	return false;
}

function isOwnedPaymentContext(
	value: OwnedPaymentContext | null,
	principal: { readonly siteId: string; readonly subject: PaymentSubject },
	siteId: string,
	intentId: string,
): value is OwnedPaymentContext {
	if (!isPlainObject(value) || !isPlainObject(value.subject)) return false;
	return value.siteId === siteId && value.siteId === principal.siteId &&
		value.subject.kind === principal.subject.kind && value.subject.id === principal.subject.id &&
		value.intentId === intentId && IDENTIFIER.test(value.merchantProfile);
}

function isMoney(value: unknown): value is { readonly currency: 'NGN'; readonly value: string } {
	return isPlainObject(value) && hasExactKeys(value, ['currency', 'value']) &&
		value.currency === 'NGN' && isCanonicalAmount(value.value);
}

function isScalarMap(value: unknown, keyPattern: RegExp, fieldValues: boolean): boolean {
	if (!isPlainObject(value) || Object.keys(value).length > (fieldValues ? 20 : 64)) return false;
	for (const [key, item] of Object.entries(value)) {
		if (!keyPattern.test(key) || !(typeof item === 'string' || typeof item === 'boolean' ||
			(!fieldValues && (typeof item === 'number' && Number.isSafeInteger(item) || item === null)))) return false;
		if (typeof item === 'string' && item.length > (fieldValues ? 2_000 : 4_096)) return false;
	}
	return true;
}

function hasExactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
	const allowed = new Set([...required, ...optional]);
	return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
	const prototype = Object.getPrototypeOf(value);
	return prototype === null || prototype === Object.prototype;
}

function isIdentifier(value: unknown): value is string {
	return typeof value === 'string' && IDENTIFIER.test(value);
}

function isIntentId(value: unknown): value is string {
	return typeof value === 'string' && INTENT_ID.test(value);
}

function isAttemptId(value: unknown): value is string {
	return typeof value === 'string' && ATTEMPT_ID.test(value);
}

function isCanonicalAmount(value: unknown): value is string {
	return typeof value === 'string' && value.length <= 32 && CANONICAL_AMOUNT.test(value);
}

function isPersistentBoundaryConfigured(options: PaystackSiteAdapterOptions): boolean {
	return options.store?.durable === true && options.limiter?.durable === true;
}

function isAdapterConfigurationValid(options: PaystackSiteAdapterOptions): boolean {
	return isIdentifier(options.installedPluginId) && isIdentifier(options.siteId) && isIdentifier(options.keyId) &&
		options.siteAttestationKey instanceof Uint8Array && options.siteAttestationKey.byteLength === 32 &&
		options.identityHmacKey instanceof Uint8Array && options.identityHmacKey.byteLength === 32 &&
		!constantTimeEqual(options.siteAttestationKey, options.identityHmacKey);
}

async function bindIdentityKey(options: PaystackSiteAdapterOptions, cryptoProvider: Crypto): Promise<boolean> {
	const fingerprint = await identityKeyFingerprint(options.identityHmacKey, cryptoProvider);
	return options.store!.bindIdentityKeyFingerprint(fingerprint);
}

async function deriveDigest(keyBytes: Uint8Array, parts: readonly string[], cryptoProvider: Crypto): Promise<string> {
	const frame = ['emdash-paystack-site-partition-v1', ...parts.map((part) => `${new TextEncoder().encode(part).byteLength}:${part}`)].join('\n');
	const key = await cryptoProvider.subtle.importKey('raw', toArrayBuffer(keyBytes), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const digest = new Uint8Array(await cryptoProvider.subtle.sign('HMAC', key, toArrayBuffer(new TextEncoder().encode(frame))));
	return toHex(digest);
}

function domainResponse(result: DomainResult<unknown>): Response {
	if (!result.ok) return errorResponse(result.error.code, toSiteHttpStatus(result));
	const status = validateAttemptStatus(result.value);
	if (!status) return errorResponse('provider_unavailable', 503);
	if (status.state === 'review_required') return jsonResponse(status, 409);
	const accepted = ['created', 'initializing', 'requires_action', 'pending', 'unknown'].includes(String(status.state));
	return jsonResponse(status, accepted ? 202 : 200);
}

function isAdmissionPending(value: unknown): boolean {
	return isPlainObject(value) && value.state === 'initializing' &&
		(value.stage === 'admission' || value.stage === 'allocation');
}

function validateAttemptStatus(value: unknown): Record<string, unknown> | null {
	if (!isPlainObject(value)) return null;
	const allowed = new Set(['schemaVersion', 'intentId', 'attemptId', 'state', 'outcome', 'nextAction', 'amount', 'deliveryState', 'paymentId', 'stage']);
	if (Object.keys(value).some((key) => !allowed.has(key)) || value.schemaVersion !== '1.0' ||
		!isIntentId(value.intentId) || !['created', 'initializing', 'requires_action', 'pending', 'unknown', 'verified_paid',
			'verified_failed', 'verified_canceled', 'review_required'].includes(String(value.state)) ||
		!['not_eligible', 'pending', 'acknowledged'].includes(String(value.deliveryState))) return null;
	if (value.attemptId !== undefined && !isAttemptId(value.attemptId)) return null;
	if (value.outcome !== undefined && !['existing_intent', 'new_attempt'].includes(String(value.outcome))) return null;
	if (value.paymentId !== undefined && !isIdentifier(value.paymentId)) return null;
	if (value.stage !== undefined && !['admission', 'allocation', 'provider_work', 'verification', 'complete'].includes(String(value.stage))) return null;
	if (value.amount !== undefined && (!isMoney(value.amount))) return null;
	if (value.nextAction !== undefined && !isSafeNextAction(value.nextAction)) return null;
	return value;
}

function isSafeNextAction(value: unknown): boolean {
	if (!isPlainObject(value) || !hasExactKeys(value, ['id', 'kind', 'destination']) ||
		!isAttemptId(value.id) || value.kind !== 'redirect') return false;
	const destinationValue = value.destination;
	if (typeof destinationValue !== 'string') return false;
	try {
		const destination = new URL(destinationValue);
		return destination.origin === 'https://checkout.paystack.com' && !destination.username && !destination.password;
	} catch {
		return false;
	}
}

function isSameSiteCallback(value: unknown, siteOrigin: string): value is string {
	if (typeof value !== 'string' || value.length < 1 || value.length > 2_048) return false;
	try {
		const site = new URL(siteOrigin);
		const callback = new URL(value);
		return site.protocol === 'https:' && site.origin === siteOrigin && site.username === '' && site.password === '' &&
			callback.protocol === 'https:' && callback.origin === site.origin && callback.username === '' && callback.password === '' &&
			callback.search === '' && callback.hash === '' && callback.pathname.startsWith('/') && callback.pathname.length <= 512;
	} catch {
		return false;
	}
}

function errorResponse(code: SafeErrorCode, status: number): Response {
	const error = safeError(code);
	return jsonResponse({ code: error.code, message: error.message }, status);
}

function jsonResponse(value: unknown, status: number): Response {
	return new Response(JSON.stringify(value), {
		status,
		headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'private, no-store' },
	});
}

function encodeBase64Url(bytes: Uint8Array): string {
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const copy = new ArrayBuffer(bytes.byteLength);
	new Uint8Array(copy).set(bytes);
	return copy;
}

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
	if (left.byteLength !== right.byteLength) return false;
	let diff = 0;
	for (let index = 0; index < left.byteLength; index += 1) diff |= left[index]! ^ right[index]!;
	return diff === 0;
}
