import { hmacIndex, encodeBase64Url, decodeBase64Url, type IndexHmacKey } from '../security/encryption.js';
import { parseStrictJson } from '../security/json.js';
import { isPlainObject } from './schema.js';

export const INSPECTION_CURSOR_TTL_MS = 15 * 60_000;
const MAX_CURSOR_BYTES = 4_096;
const MAX_STORAGE_CURSOR_BYTES = 2_048;

export type InspectionView = 'customers' | 'payments' | 'payment-detail' | 'webhook-events' | 'result-feed';
export type InspectionSort = 'createdAt:desc' | 'createdAt:asc' | 'verifiedAt:asc';

export interface InspectionCursorContext {
	readonly siteBinding: string;
	readonly view: InspectionView;
	readonly filter: string | null;
	readonly sort: InspectionSort;
	readonly limit: number;
}

export interface InspectionCursorKeys {
	readonly activeKeyId: string;
	readonly keys: readonly IndexHmacKey[];
}

interface CursorPayload {
	readonly version: 1;
	readonly keyId: string;
	readonly storageCursor: string;
	readonly expiresAt: number;
}

/** Sign the host cursor together with the exact inspection scope and an expiry. */
export async function signInspectionCursor(
	storageCursor: string,
	context: InspectionCursorContext,
	keys: InspectionCursorKeys,
	nowMs: number,
	cryptoProvider: Crypto = globalThis.crypto,
): Promise<string | null> {
	if (!isStorageCursor(storageCursor) || !isCursorContext(context) || !isCursorKeys(keys) || !isClock(nowMs)) return null;
	const key = keys.keys.find((candidate) => candidate.keyId === keys.activeKeyId);
	if (!key) return null;
	const expiresAt = nowMs + INSPECTION_CURSOR_TTL_MS;
	if (!Number.isSafeInteger(expiresAt)) return null;
	const payload: CursorPayload = Object.freeze({ version: 1, keyId: key.keyId, storageCursor, expiresAt });
	try {
		const body = encodeBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
		const signature = await signFrame(payload, context, key, cryptoProvider);
		return `v1.${key.keyId}.${body}.${signature}`;
	} catch {
		return null;
	}
}

/** Verify expiry, retained key version, site/view/filter/sort/page-size scope and storage cursor. */
export async function verifyInspectionCursor(
	cursor: unknown,
	context: InspectionCursorContext,
	keys: InspectionCursorKeys,
	nowMs: number,
	cryptoProvider: Crypto = globalThis.crypto,
): Promise<string | null> {
	if (typeof cursor !== 'string' || cursor.length > MAX_CURSOR_BYTES || !isCursorContext(context) ||
		!isCursorKeys(keys) || !isClock(nowMs)) return null;
	const parts = cursor.split('.');
	if (parts.length !== 4 || parts[0] !== 'v1' || !/^[A-Za-z0-9_-]{1,64}$/u.test(parts[1]!) ||
		!/^[a-f0-9]{64}$/u.test(parts[3]!)) return null;
	const keyId = parts[1]!;
	const key = keys.keys.find((candidate) => candidate.keyId === keyId);
	if (!key) return null;
	let payload: unknown;
	try {
		const bytes = decodeBase64Url(parts[2]!);
		if (bytes.byteLength > MAX_CURSOR_BYTES) return null;
		payload = parseStrictJson(bytes, MAX_CURSOR_BYTES);
	} catch {
		return null;
	}
	if (!isCursorPayload(payload) || payload.keyId !== keyId || payload.expiresAt <= nowMs ||
		payload.expiresAt > nowMs + INSPECTION_CURSOR_TTL_MS || !isStorageCursor(payload.storageCursor)) return null;
	try {
		const expected = await signFrame(payload, context, key, cryptoProvider);
		return constantTimeHexEqual(expected, parts[3]!) ? payload.storageCursor : null;
	} catch {
		return null;
	}
}

async function signFrame(
	payload: CursorPayload,
	context: InspectionCursorContext,
	key: IndexHmacKey,
	cryptoProvider: Crypto,
): Promise<string> {
	return hmacIndex([
		'paystack-admin-inspection-cursor-v1',
		payload.keyId,
		context.siteBinding,
		context.view,
		context.filter ?? '',
		context.sort,
		String(context.limit),
		payload.storageCursor,
		String(payload.expiresAt),
	], key, cryptoProvider);
}

function isCursorPayload(value: unknown): value is CursorPayload {
	return isPlainObject(value) && Object.keys(value).length === 4 &&
		Object.hasOwn(value, 'version') && Object.hasOwn(value, 'keyId') &&
		Object.hasOwn(value, 'storageCursor') && Object.hasOwn(value, 'expiresAt') &&
		value.version === 1 && typeof value.keyId === 'string' && /^[A-Za-z0-9_-]{1,64}$/u.test(value.keyId) &&
		typeof value.storageCursor === 'string' && Number.isSafeInteger(value.expiresAt) && typeof value.expiresAt === 'number';
}

function isCursorKeys(value: InspectionCursorKeys): boolean {
	return Boolean(value && typeof value.activeKeyId === 'string' && /^[A-Za-z0-9_-]{1,64}$/u.test(value.activeKeyId) &&
		Array.isArray(value.keys) && value.keys.length >= 1 && value.keys.length <= 16 &&
		value.keys.every((key) => key?.usage === 'identity-index' && /^[A-Za-z0-9_-]{1,64}$/u.test(key.keyId) &&
			key.material instanceof Uint8Array && key.material.byteLength === 32) &&
		new Set(value.keys.map((key) => key.keyId)).size === value.keys.length &&
		value.keys.some((key) => key.keyId === value.activeKeyId));
}

function isCursorContext(value: InspectionCursorContext): boolean {
	return Boolean(value && typeof value.siteBinding === 'string' && value.siteBinding.length > 0 && value.siteBinding.length <= 512 &&
		!/[\u0000-\u001f\u007f]/u.test(value.siteBinding) &&
		(value.view === 'customers' || value.view === 'payments' || value.view === 'payment-detail' || value.view === 'webhook-events' || value.view === 'result-feed') &&
		(value.filter === null || typeof value.filter === 'string' && value.filter.length <= 120 && !/[\u0000-\u001f\u007f]/u.test(value.filter)) &&
		(value.sort === 'createdAt:desc' || value.sort === 'createdAt:asc' || value.sort === 'verifiedAt:asc') &&
		Number.isSafeInteger(value.limit) && value.limit >= 1 && value.limit <= 50);
}

function isStorageCursor(value: unknown): value is string {
	return typeof value === 'string' && value.length > 0 && value.length <= MAX_STORAGE_CURSOR_BYTES && /^[\x21-\x7e]+$/u.test(value);
}

function isClock(value: number): boolean {
	return Number.isSafeInteger(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER - INSPECTION_CURSOR_TTL_MS;
}

function constantTimeHexEqual(left: string, right: string): boolean {
	if (!/^[a-f0-9]{64}$/u.test(left) || !/^[a-f0-9]{64}$/u.test(right)) return false;
	let difference = 0;
	for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
	return difference === 0;
}
