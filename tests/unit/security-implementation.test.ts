import { describe, expect, it } from 'vite-plus/test';
import {
	createDataEncryptionKey,
	createIndexHmacKey,
	assertDistinctCryptoKeys,
	decryptValue,
	encryptValue,
	hmacIndex,
	type AadContext,
} from '../../src/security/encryption.js';
import { canonicalJson, deriveIntentFingerprint, deriveIntentIdentity } from '../../src/domain/identity.js';

const context: AadContext = {
	pluginId: 'paystack',
	collection: 'intents',
	recordId: 'opaque-record-id',
	schemaVersion: 1,
	purpose: 'payer_email',
};

describe('purpose-separated encryption and deterministic identity implementation', () => {
	it('encrypts JSON values with a random 96-bit IV and decrypts only with matching record AAD', async () => {
		const key = createDataEncryptionKey('pii-v1', new Uint8Array(32).fill(7));
		const first = await encryptValue({ email: 'private@example.test' }, key, context);
		const second = await encryptValue({ email: 'private@example.test' }, key, context);
		expect(first.iv).toHaveLength(16);
		expect(first.iv).not.toBe(second.iv);
		expect(first).not.toHaveProperty('plaintext');
		expect(await decryptValue(first, new Map([[key.keyId, key]]), context)).toEqual({ email: 'private@example.test' });
		await expect(decryptValue(first, new Map([[key.keyId, key]]), { ...context, purpose: 'subject' })).rejects.toThrow('DECRYPTION_FAILED');
		await expect(decryptValue(first, new Map(), context)).rejects.toThrow('ENCRYPTION_KEY_UNAVAILABLE');
	});

	it('keeps index HMACs deterministic, opaque and purpose typed', async () => {
		const key = createIndexHmacKey('identity-v1', new Uint8Array(32).fill(9));
		const a = await hmacIndex(['intent', 'member_1', 'order_1'], key);
		const b = await hmacIndex(['intent', 'member_1', 'order_1'], key);
		expect(a).toBe(b);
		expect(a).toMatch(/^[a-f0-9]{64}$/);
		expect(a).not.toContain('member_1');
	});

	it('rejects reuse of key material across field, index, attestation and result-consumer purposes', () => {
		const material = new Uint8Array(32).fill(11);
		expect(() => assertDistinctCryptoKeys([
			{ usage: 'field-encryption', keyId: 'data-1', material },
			{ usage: 'identity-index', keyId: 'index-1', material: material.slice() },
		])).toThrow('KEY_PURPOSE_REUSE');
		expect(() => assertDistinctCryptoKeys([
			{ usage: 'site-attestation', keyId: 'attest-1', material: new Uint8Array(32).fill(1) },
			{ usage: 'result-consumer', keyId: 'result-1', material: new Uint8Array(32).fill(2) },
		])).not.toThrow();
	});

	it('derives stable intent identity independent of request transport keys', async () => {
		const key = createIndexHmacKey('identity-v1', new Uint8Array(32).fill(3));
		const identity = {
			siteId: 'site_1',
			subject: { kind: 'member', id: 'member_1' },
			merchantId: 'merchant_1',
			environment: 'test' as const,
			businessReference: 'order_1',
		};
		expect(await deriveIntentIdentity(identity, key)).toBe(await deriveIntentIdentity(identity, key));
	});

	it('canonicalizes object key order and rejects reserved keys and unsafe integer identity values', async () => {
		expect(canonicalJson({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
		expect(() => canonicalJson(JSON.parse('{"__proto__":{"polluted":true}}'))).toThrow('RESERVED_KEY');
		const key = createIndexHmacKey('identity-v1', new Uint8Array(32).fill(4));
		const common = {
			formId: 'form', formRevision: 'r1', pricingMode: 'fixed' as const,
			amountMinor: '5000', method: 'card' as const, returnPolicy: 'site-default',
		};
		const a = await deriveIntentFingerprint({ ...common, fields: { b: '2', a: '1' }, metadata: {} }, key);
		const b = await deriveIntentFingerprint({ ...common, fields: { a: '1', b: '2' }, metadata: {} }, key);
		expect(a).toBe(b);
		await expect(deriveIntentFingerprint({ ...common, fields: { order: Number.MAX_SAFE_INTEGER + 1 }, metadata: {} }, key)).rejects.toThrow('UNSAFE_NUMBER');
	});
});
