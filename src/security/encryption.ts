import { isPlainObject, MAX_AGGREGATE_BYTES, StorageInvariantError } from '../storage/schema.js';

export type FieldPurpose =
	| 'payer_email'
	| 'subject'
	| 'business_reference'
	| 'custom_fields'
	| 'metadata'
	| 'account_details'
	| 'hosted_action_url';

export interface DataEncryptionKey {
	readonly usage: 'field-encryption';
	readonly keyId: string;
	readonly material: Uint8Array;
}

export interface IndexHmacKey {
	readonly usage: 'identity-index';
	readonly keyId: string;
	readonly material: Uint8Array;
}

export interface ScopedCryptoKey {
	readonly usage: 'field-encryption' | 'identity-index' | 'site-attestation' | 'result-consumer';
	readonly keyId: string;
	readonly material: Uint8Array;
}

export interface AadContext {
	readonly pluginId: string;
	readonly collection: string;
	readonly recordId: string;
	readonly schemaVersion: number;
	readonly purpose: FieldPurpose;
}

export interface AesGcmEnvelope {
	readonly version: 1;
	readonly algorithm: 'A256GCM';
	readonly keyId: string;
	readonly iv: string;
	readonly ciphertext: string;
}

export function createDataEncryptionKey(keyId: string, material: Uint8Array): DataEncryptionKey {
	assertKeyId(keyId);
	assertAesKey(material);
	return { usage: 'field-encryption', keyId, material: material.slice() };
}

export function createIndexHmacKey(keyId: string, material: Uint8Array): IndexHmacKey {
	assertKeyId(keyId);
	assertAesKey(material);
	return { usage: 'identity-index', keyId, material: material.slice() };
}

/** Reject key reuse across cryptographic purposes before a key ring is persisted or activated. */
export function assertDistinctCryptoKeys(keys: readonly ScopedCryptoKey[]): void {
	for (const key of keys) {
		assertKeyId(key.keyId);
		assertAesKey(key.material);
	}
	for (let left = 0; left < keys.length; left += 1) {
		for (let right = left + 1; right < keys.length; right += 1) {
			const a = keys[left]!;
			const b = keys[right]!;
			if (a.usage !== b.usage && equalBytes(a.material, b.material)) {
				throw new StorageInvariantError('KEY_PURPOSE_REUSE');
			}
			if (a.usage === b.usage && a.keyId === b.keyId) {
				throw new StorageInvariantError('DUPLICATE_KEY_ID');
			}
		}
	}
}

export async function encryptValue(
	value: unknown,
	key: DataEncryptionKey,
	context: AadContext,
	cryptoProvider: Crypto = globalThis.crypto,
): Promise<AesGcmEnvelope> {
	assertDataKey(key);
	assertAadContext(context);
	let serialized: string;
	try {
		serialized = JSON.stringify(value);
	} catch {
		throw new StorageInvariantError('UNSERIALIZABLE_SECRET');
	}
	if (typeof serialized !== 'string') throw new StorageInvariantError('UNSERIALIZABLE_SECRET');
	const plaintext = new TextEncoder().encode(serialized);
	if (plaintext.byteLength > MAX_AGGREGATE_BYTES) throw new StorageInvariantError('SECRET_TOO_LARGE');
	const iv = cryptoProvider.getRandomValues(new Uint8Array(12));
	const cryptoKey = await cryptoProvider.subtle.importKey('raw', toArrayBuffer(key.material), 'AES-GCM', false, ['encrypt']);
	const encrypted = await cryptoProvider.subtle.encrypt(
		{ name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: toArrayBuffer(encodeAad(context)), tagLength: 128 },
		cryptoKey,
		toArrayBuffer(plaintext),
	);
	return {
		version: 1,
		algorithm: 'A256GCM',
		keyId: key.keyId,
		iv: encodeBase64Url(iv),
		ciphertext: encodeBase64Url(new Uint8Array(encrypted)),
	};
}

export async function decryptValue<T = unknown>(
	envelope: unknown,
	keys: ReadonlyMap<string, DataEncryptionKey>,
	context: AadContext,
	cryptoProvider: Crypto = globalThis.crypto,
): Promise<T> {
	assertAadContext(context);
	if (!isPlainObject(envelope) || envelope.version !== 1 || envelope.algorithm !== 'A256GCM') {
		throw new StorageInvariantError('INVALID_ENCRYPTED_ENVELOPE');
	}
	if (typeof envelope.keyId !== 'string' || typeof envelope.iv !== 'string' || typeof envelope.ciphertext !== 'string') {
		throw new StorageInvariantError('INVALID_ENCRYPTED_ENVELOPE');
	}
	const key = keys.get(envelope.keyId);
	if (!key || key.keyId !== envelope.keyId) throw new StorageInvariantError('ENCRYPTION_KEY_UNAVAILABLE');
	assertDataKey(key);
	const iv = decodeBase64Url(envelope.iv);
	const ciphertext = decodeBase64Url(envelope.ciphertext);
	if (iv.byteLength !== 12 || ciphertext.byteLength < 16 || ciphertext.byteLength > MAX_AGGREGATE_BYTES + 16) {
		throw new StorageInvariantError('INVALID_ENCRYPTED_ENVELOPE');
	}
	try {
		const cryptoKey = await cryptoProvider.subtle.importKey('raw', toArrayBuffer(key.material), 'AES-GCM', false, ['decrypt']);
		const plaintext = await cryptoProvider.subtle.decrypt(
			{ name: 'AES-GCM', iv: toArrayBuffer(iv), additionalData: toArrayBuffer(encodeAad(context)), tagLength: 128 },
			cryptoKey,
			toArrayBuffer(ciphertext),
		);
		const decoded = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
		return JSON.parse(decoded) as T;
	} catch {
		// Wrong key, purpose, record, schema or damaged ciphertext all fail closed.
		throw new StorageInvariantError('DECRYPTION_FAILED');
	}
}

/** Re-encrypt one versioned field without dropping the historical key needed by unprocessed records. */
export async function rotateEncryptedEnvelope<T = unknown>(
	envelope: unknown,
	keys: ReadonlyMap<string, DataEncryptionKey>,
	activeKey: DataEncryptionKey,
	context: AadContext,
	cryptoProvider: Crypto = globalThis.crypto,
): Promise<AesGcmEnvelope> {
	assertDataKey(activeKey);
	if (!isPlainObject(envelope) || typeof envelope.keyId !== 'string') {
		throw new StorageInvariantError('INVALID_ENCRYPTED_ENVELOPE');
	}
	if (envelope.keyId === activeKey.keyId) {
		await decryptValue(envelope, keys, context, cryptoProvider);
		return envelope as unknown as AesGcmEnvelope;
	}
	const value = await decryptValue<T>(envelope, keys, context, cryptoProvider);
	return encryptValue(value, activeKey, context, cryptoProvider);
}

export async function hmacIndex(
	parts: readonly string[],
	key: IndexHmacKey,
	cryptoProvider: Crypto = globalThis.crypto,
): Promise<string> {
	assertIndexKey(key);
	if (parts.length === 0 || parts.some((part) => typeof part !== 'string' || part.length > 4096)) {
		throw new StorageInvariantError('INVALID_IDENTITY_PARTS');
	}
	const message = encodeTuple(parts);
	const cryptoKey = await cryptoProvider.subtle.importKey('raw', toArrayBuffer(key.material), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	return toHex(new Uint8Array(await cryptoProvider.subtle.sign('HMAC', cryptoKey, toArrayBuffer(message))));
}

export function encodeTuple(parts: readonly string[]): Uint8Array {
	const encoded = parts.map((part) => {
		const bytes = new TextEncoder().encode(part);
		return `${bytes.byteLength}:` + part;
	});
	return new TextEncoder().encode(encoded.join(''));
}

export function encodeAad(context: AadContext): Uint8Array {
	assertAadContext(context);
	return encodeTuple([
		context.pluginId,
		context.collection,
		context.recordId,
		String(context.schemaVersion),
		context.purpose,
	]);
}

export function encodeBase64Url(bytes: Uint8Array): string {
	let binary = '';
	for (let offset = 0; offset < bytes.length; offset += 0x8000) {
		binary += String.fromCharCode(...bytes.subarray(offset, Math.min(offset + 0x8000, bytes.length)));
	}
	return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
}

export function decodeBase64Url(value: string): Uint8Array {
	if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) {
		throw new StorageInvariantError('INVALID_BASE64URL');
	}
	const base64 = value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - (value.length % 4)) % 4);
	try {
		const binary = atob(base64);
		const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
		if (encodeBase64Url(bytes) !== value) throw new Error('noncanonical');
		return bytes;
	} catch {
		throw new StorageInvariantError('INVALID_BASE64URL');
	}
}

export function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function assertKeyId(keyId: string): void {
	if (!/^[A-Za-z0-9_-]{1,64}$/.test(keyId)) throw new StorageInvariantError('INVALID_KEY_ID');
}

function assertAesKey(material: Uint8Array): void {
	if (!(material instanceof Uint8Array) || material.byteLength !== 32) {
		throw new StorageInvariantError('INVALID_KEY_MATERIAL');
	}
}

function assertDataKey(key: DataEncryptionKey): void {
	if (!key || key.usage !== 'field-encryption') throw new StorageInvariantError('WRONG_KEY_PURPOSE');
	assertKeyId(key.keyId);
	assertAesKey(key.material);
}

function assertIndexKey(key: IndexHmacKey): void {
	if (!key || key.usage !== 'identity-index') throw new StorageInvariantError('WRONG_KEY_PURPOSE');
	assertKeyId(key.keyId);
	assertAesKey(key.material);
}

function assertAadContext(context: AadContext): void {
	if (
		!context ||
		![context.pluginId, context.collection, context.recordId].every(
			(value) => typeof value === 'string' && value.length > 0 && value.length <= 128 && !/[\r\n]/.test(value),
		) ||
		!Number.isSafeInteger(context.schemaVersion) ||
		context.schemaVersion < 1 ||
		!['payer_email', 'subject', 'business_reference', 'custom_fields', 'metadata', 'account_details', 'hosted_action_url'].includes(context.purpose)
	) {
		throw new StorageInvariantError('INVALID_AAD_CONTEXT');
	}
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const buffer = new ArrayBuffer(bytes.byteLength);
	new Uint8Array(buffer).set(bytes);
	return buffer;
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
	if (left.byteLength !== right.byteLength) return false;
	let difference = 0;
	for (let index = 0; index < left.byteLength; index += 1) difference |= left[index]! ^ right[index]!;
	return difference === 0;
}


/** Decode the field encryption keys used for current and historical envelopes. */
export function readFieldEncryptionKeys(
	stored: readonly { readonly keyId: string; readonly material: string }[],
): ReadonlyMap<string, DataEncryptionKey> | null {
	const keys = new Map<string, DataEncryptionKey>();
	try {
		for (const entry of stored) {
			keys.set(entry.keyId, createDataEncryptionKey(entry.keyId, decodeBase64Url(entry.material)));
		}
		return keys;
	} catch {
		return null;
	}
}
