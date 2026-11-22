import { hmacIndex, type IndexHmacKey } from './encryption.js';
import { MAX_STRICT_JSON_BYTES, parseStrictJson } from './json.js';
import { deterministicRecordId, type VersionedCollection } from '../storage/schema.js';

export const MAX_ATTESTED_BODY_BYTES = MAX_STRICT_JSON_BYTES;
export const MAX_CLOCK_SKEW_SECONDS = 60;
export const NONCE_RETENTION_MS = 5 * 60_000;
export const MAX_PREVIOUS_KEY_OVERLAP_MS = 5 * 60_000;

export type AttestationPurpose = 'site-payment' | 'privacy:erase' | 'result-consumer';

export interface SiteAttestationKey {
	readonly provider: 'paystack';
	readonly siteId: string;
	readonly keyId: string;
	readonly purpose: AttestationPurpose;
	readonly material: Uint8Array;
	readonly state: 'current' | 'previous' | 'revoked';
	readonly previousSinceMs?: number;
	readonly previousUntilMs?: number;
}

export interface AttestationHeaders {
	readonly 'x-payment-site-id'?: string;
	readonly 'x-payment-key-id'?: string;
	readonly 'x-payment-timestamp'?: string;
	readonly 'x-payment-nonce'?: string;
	readonly 'x-payment-signature'?: string;
}

export interface AttestationRequest {
	readonly provider: 'paystack';
	readonly method: string;
	readonly route: string;
	readonly rawBody: Uint8Array;
	readonly headers: AttestationHeaders;
	readonly nowMs: number;
	readonly keys: readonly SiteAttestationKey[];
}

export interface VerifiedAttestation {
	readonly siteId: string;
	readonly keyId: string;
	readonly purpose: AttestationPurpose;
	readonly route: string;
	readonly nonce: string;
	readonly bodyDigest: string;
	readonly timestampSeconds: number;
}

export interface NonceRecord {
	readonly modelVersion: 1;
	readonly expiresAt: number;
	readonly acceptedAt: number;
	readonly requestDigest: string;
}

export type AttestationResult<T = unknown> =
	| { readonly ok: true; readonly attestation: VerifiedAttestation; readonly body: T }
	| { readonly ok: false; readonly code: 'unauthorized' | 'invalid_request' | 'replay' | 'temporarily_unavailable' };

const ROUTE_PURPOSES: Readonly<Record<string, readonly AttestationPurpose[]>> = {
	'payments/submit': ['site-payment'],
	'payments/action': ['site-payment'],
	'payments/status': ['site-payment'],
	'customers/erase': ['privacy:erase'],
	'results/feed': ['result-consumer'],
	'results/ack': ['result-consumer'],
};

export async function verifySiteAttestation(
	request: AttestationRequest,
	cryptoProvider: Crypto = globalThis.crypto,
): Promise<VerifiedAttestation | null> {
	if (
		request.provider !== 'paystack' ||
		!(request.rawBody instanceof Uint8Array) ||
		request.rawBody.byteLength > MAX_ATTESTED_BODY_BYTES ||
		!Number.isSafeInteger(request.nowMs) || request.nowMs < 0 ||
		!isStaticRoute(request.route) ||
		!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method) || request.method !== request.method.toUpperCase()
	) return null;

	const siteId = singletonAscii(request.headers['x-payment-site-id'], /^[A-Za-z0-9_-]{1,120}$/);
	const keyId = singletonAscii(request.headers['x-payment-key-id'], /^[A-Za-z0-9_-]{1,120}$/);
	const timestamp = singletonAscii(request.headers['x-payment-timestamp'], /^(0|[1-9][0-9]{0,11})$/);
	const nonce = singletonAscii(request.headers['x-payment-nonce'], /^[A-Za-z0-9_-]{16,64}$/);
	const signature = singletonAscii(request.headers['x-payment-signature'], /^[a-f0-9]{64}$/);
	if (!siteId || !keyId || !timestamp || !nonce || !signature) return null;
	const timestampSeconds = Number(timestamp);
	const nowSeconds = Math.floor(request.nowMs / 1000);
	if (!Number.isSafeInteger(timestampSeconds) || Math.abs(nowSeconds - timestampSeconds) > MAX_CLOCK_SKEW_SECONDS) return null;
	const allowedPurposes = ROUTE_PURPOSES[request.route];
	if (!allowedPurposes) return null;
	const key = request.keys.find((candidate) => candidate.keyId === keyId && candidate.siteId === siteId);
	if (!key || !isUsableKey(key, request.nowMs) || !allowedPurposes.includes(key.purpose)) return null;

	try {
		const bodyDigest = toHex(new Uint8Array(await cryptoProvider.subtle.digest('SHA-256', toArrayBuffer(request.rawBody))));
		const frame = [
			'EMDASH-PAYMENT-SITE-V1',
			'paystack',
			siteId,
			keyId,
			timestamp,
			nonce,
			request.method,
			request.route,
			bodyDigest,
		].join('\n');
		const cryptoKey = await cryptoProvider.subtle.importKey(
			'raw', toArrayBuffer(key.material), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'],
		);
		const valid = await cryptoProvider.subtle.verify(
			'HMAC', cryptoKey, toArrayBuffer(fromHex(signature)), toArrayBuffer(new TextEncoder().encode(frame)),
		);
		if (!valid) return null;
		return { siteId, keyId, purpose: key.purpose, route: request.route, nonce, bodyDigest, timestampSeconds };
	} catch {
		return null;
	}
}

export async function authenticateAndParse<T = unknown>(
	request: AttestationRequest,
	nonceIndexKey: IndexHmacKey,
	nonceCollection: Pick<VersionedCollection<NonceRecord>, 'compareAndSet'>,
	cryptoProvider: Crypto = globalThis.crypto,
): Promise<AttestationResult<T>> {
	const attestation = await verifySiteAttestation(request, cryptoProvider);
	if (!attestation) return { ok: false, code: 'unauthorized' };
	let recordId: string;
	try {
		const nonceDigest = await hmacIndex(
			['paystack-site-nonce-v1', attestation.siteId, attestation.keyId, attestation.nonce],
			nonceIndexKey,
			cryptoProvider,
		);
		recordId = deterministicRecordId('nonces', nonceDigest);
	} catch {
		return { ok: false, code: 'temporarily_unavailable' };
	}
	try {
		const acceptedAt = request.nowMs;
		const stored = await nonceCollection.compareAndSet(recordId, null, {
			modelVersion: 1,
			expiresAt: acceptedAt + NONCE_RETENTION_MS,
			acceptedAt,
			requestDigest: attestation.bodyDigest,
		});
		if (!stored.applied) return { ok: false, code: 'replay' };
	} catch {
		return { ok: false, code: 'temporarily_unavailable' };
	}
	try {
		const body = parseStrictJson(request.rawBody) as T;
		if (body && typeof body === 'object' && !Array.isArray(body)) {
			const bodySite = (body as Record<string, unknown>).siteId;
			if (bodySite !== undefined && bodySite !== attestation.siteId) return { ok: false, code: 'unauthorized' };
		}
		return { ok: true, attestation, body };
	} catch {
		return { ok: false, code: 'invalid_request' };
	}
}

export function canonicalAttestationFrame(input: {
	readonly siteId: string;
	readonly keyId: string;
	readonly timestampSeconds: number;
	readonly nonce: string;
	readonly method: string;
	readonly route: string;
	readonly bodyDigest: string;
}): string {
	return [
		'EMDASH-PAYMENT-SITE-V1', 'paystack', input.siteId, input.keyId,
		String(input.timestampSeconds), input.nonce, input.method, input.route, input.bodyDigest,
	].join('\n');
}

function isUsableKey(key: SiteAttestationKey, nowMs: number): boolean {
	if (key.provider !== 'paystack' || key.state === 'revoked' || key.material.byteLength !== 32) return false;
	if (key.state === 'current') return true;
	const { previousSinceMs, previousUntilMs } = key;
	return Number.isSafeInteger(previousSinceMs) && Number.isSafeInteger(previousUntilMs) &&
		previousSinceMs! <= nowMs && previousUntilMs! >= nowMs &&
		previousUntilMs! - previousSinceMs! <= MAX_PREVIOUS_KEY_OVERLAP_MS;
}

function isStaticRoute(route: string): boolean {
	return Object.hasOwn(ROUTE_PURPOSES, route) && /^[a-z][a-z0-9]*(?:\/[a-z][a-z0-9-]*)*$/u.test(route);
}

function singletonAscii(value: string | undefined, pattern: RegExp): string | null {
	if (typeof value !== 'string' || value.length > 256 || /[^\x21-\x7e]/u.test(value) || !pattern.test(value)) return null;
	return value;
}

function fromHex(value: string): Uint8Array {
	const bytes = new Uint8Array(value.length / 2);
	for (let index = 0; index < bytes.length; index += 1) bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
	return bytes;
}

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const buffer = new ArrayBuffer(bytes.byteLength);
	new Uint8Array(buffer).set(bytes);
	return buffer;
}
