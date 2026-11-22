import { describe, expect, it } from 'vite-plus/test';
import {
	authenticateAndParse,
	canonicalAttestationFrame,
	MAX_PREVIOUS_KEY_OVERLAP_MS,
	NONCE_RETENTION_MS,
	verifySiteAttestation,
	type AttestationHeaders,
	type AttestationRequest,
	type NonceRecord,
	type SiteAttestationKey,
} from '../../src/security/attestation.js';
import { createIndexHmacKey } from '../../src/security/encryption.js';

const nowMs = Date.parse('2026-10-18T00:00:00.000Z');
const material = new Uint8Array(32).fill(23);
const key: SiteAttestationKey = {
	provider: 'paystack',
	siteId: 'site_001',
	keyId: 'site_key_001',
	purpose: 'site-payment',
	material,
	state: 'current',
};

class NonceStore {
	readonly rows = new Map<string, NonceRecord>();
	calls = 0;
	fail = false;

	async compareAndSet(id: string, expectedRevision: string | null, data: NonceRecord) {
		this.calls += 1;
		if (this.fail) throw new Error('bridge failure');
		if (expectedRevision !== null || this.rows.has(id)) return { applied: false as const };
		this.rows.set(id, data);
		return { applied: true as const, revision: '1' };
	}
}

describe('site attestation and strict JSON implementation', () => {
	it('verifies the exact nine-line UTF-8 frame before parsing and reserves a five-minute nonce', async () => {
		const store = new NonceStore();
		const request = await signedRequest('{"siteId":"site_001","amount":"50.00"}');
		const parsed = await authenticateAndParse(request, createIndexHmacKey('nonce-index', new Uint8Array(32).fill(24)), store);
		expect(parsed.ok).toBe(true);
		expect(store.calls).toBe(1);
		expect(store.rows.size).toBe(1);
		const [stored] = [...store.rows.values()];
		expect(stored?.expiresAt).toBe(nowMs + NONCE_RETENTION_MS);
		if (parsed.ok) expect(parsed.attestation.purpose).toBe('site-payment');
	});

	it('rejects altered bytes, scope mismatch, replay, stale keys and out-of-window timestamps before business work', async () => {
		const request = await signedRequest('{"siteId":"site_001"}');
		const store = new NonceStore();
		const tampered = { ...request, rawBody: new TextEncoder().encode('{"siteId":"site_002"}') };
		expect(await verifySiteAttestation(tampered)).toBeNull();
		expect(store.calls).toBe(0);
		const denied = await authenticateAndParse(tampered, createIndexHmacKey('nonce-index', new Uint8Array(32).fill(24)), store);
		expect(denied).toEqual({ ok: false, code: 'unauthorized' });
		expect(store.calls).toBe(0);
		const first = await authenticateAndParse(request, createIndexHmacKey('nonce-index', new Uint8Array(32).fill(24)), store);
		expect(first.ok).toBe(true);
		const replay = await authenticateAndParse(request, createIndexHmacKey('nonce-index', new Uint8Array(32).fill(24)), store);
		expect(replay).toEqual({ ok: false, code: 'replay' });
		const stale = { ...request, nowMs: nowMs + 61_000 };
		expect(await verifySiteAttestation(stale)).toBeNull();
		const wrongScope = { ...request, route: 'results/feed' };
		expect(await verifySiteAttestation(wrongScope)).toBeNull();
		const overlongPrevious: SiteAttestationKey = {
			...key,
			state: 'previous',
			previousSinceMs: nowMs - 1,
			previousUntilMs: nowMs + MAX_PREVIOUS_KEY_OVERLAP_MS + 1,
		};
		expect(await verifySiteAttestation({ ...request, keys: [overlongPrevious] })).toBeNull();
	});

	it('rejects duplicate/reserved JSON keys, malformed UTF-8, unsafe integers and oversized frames', async () => {
		const duplicate = await signedRequest('{"siteId":"site_001","siteId":"site_001"}', 'bm9uY2VfZHVwbGljYXRlX3NhbXBsZQ');
		const store = new NonceStore();
		const indexKey = createIndexHmacKey('nonce-index', new Uint8Array(32).fill(24));
		expect(await authenticateAndParse(duplicate, indexKey, store)).toEqual({ ok: false, code: 'invalid_request' });
		const reserved = await signedRequest('{"nested":{"constructor":true}}', 'bm9uY2VfcmVzZXJ2ZWRfc2FtcGxl');
		expect(await authenticateAndParse(reserved, indexKey, store)).toEqual({ ok: false, code: 'invalid_request' });
		const unsafe = await signedRequest('{"id":9007199254740992}', 'bm9uY2VfdW5zYWZlX3NhbXBsZQ');
		expect(await authenticateAndParse(unsafe, indexKey, store)).toEqual({ ok: false, code: 'invalid_request' });
		const malformed = new Uint8Array([0xc3, 0x28]);
		const malformedRequest = await signedRequestBytes(malformed, 'bm9uY2VfbWFsZm9ybV9zYW1wbGU');
		expect(await authenticateAndParse(malformedRequest, indexKey, store)).toEqual({ ok: false, code: 'invalid_request' });
		const tooLarge = new Uint8Array(65_537).fill(32);
		expect(await verifySiteAttestation(await signedRequestBytes(tooLarge))).toBeNull();
	});

	it('fails closed on storage uncertainty and uses a fresh nonce for domain retry', async () => {
		const request = await signedRequest('{"ok":true}');
		const store = new NonceStore();
		store.fail = true;
		const result = await authenticateAndParse(request, createIndexHmacKey('nonce-index', new Uint8Array(32).fill(24)), store);
		expect(result).toEqual({ ok: false, code: 'temporarily_unavailable' });
		const retry = await signedRequest('{"ok":true}', 'bm9uY2VfMDAyX3NhbXBsZV9zaXRl');
		store.fail = false;
		expect((await authenticateAndParse(retry, createIndexHmacKey('nonce-index', new Uint8Array(32).fill(24)), store)).ok).toBe(true);
	});
});

async function signedRequest(body: string, nonce = 'bm9uY2VfMDAxX3NhbXBsZV9zaXRl'): Promise<AttestationRequest> {
	return signedRequestBytes(new TextEncoder().encode(body), nonce);
}

async function signedRequestBytes(rawBody: Uint8Array, nonce = 'bm9uY2VfMDAxX3NhbXBsZV9zaXRl'): Promise<AttestationRequest> {
	const bodyDigest = toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', toArrayBuffer(rawBody))));
	const frame = canonicalAttestationFrame({
		siteId: key.siteId,
		keyId: key.keyId,
		timestampSeconds: Math.floor(nowMs / 1000),
		nonce,
		method: 'POST',
		route: 'payments/submit',
		bodyDigest,
	});
	const cryptoKey = await crypto.subtle.importKey('raw', toArrayBuffer(material), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const signature = toHex(new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, toArrayBuffer(new TextEncoder().encode(frame)))));
	const headers: AttestationHeaders = {
		'x-payment-site-id': key.siteId,
		'x-payment-key-id': key.keyId,
		'x-payment-timestamp': String(Math.floor(nowMs / 1000)),
		'x-payment-nonce': nonce,
		'x-payment-signature': signature,
	};
	return { provider: 'paystack', method: 'POST', route: 'payments/submit', rawBody, headers, nowMs, keys: [key] };
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const buffer = new ArrayBuffer(bytes.byteLength);
	new Uint8Array(buffer).set(bytes);
	return buffer;
}

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
