import { describe, expect, it } from 'vite-plus/test';
import { createIndexHmacKey } from '../../src/security/encryption.js';
import {
	INSPECTION_CURSOR_TTL_MS,
	signInspectionCursor,
	verifyInspectionCursor,
	type InspectionCursorContext,
} from '../../src/storage/cursors.js';

const keys = {
	activeKeyId: 'identity-1',
	keys: [createIndexHmacKey('identity-1', new Uint8Array(32).fill(7))],
};

const context: InspectionCursorContext = {
	siteBinding: 'https://cms.example.test',
	view: 'payments',
	filter: 'pending',
	sort: 'createdAt:desc',
	limit: 25,
};

describe('signed admin inspection cursors', () => {
	it('round-trips the host cursor only for its exact scope', async () => {
		const cursor = await signInspectionCursor('host-page-2', context, keys, 90_000);
		expect(cursor).toMatch(/^v1\.identity-1\./u);
		expect(await verifyInspectionCursor(cursor, context, keys, 90_001)).toBe('host-page-2');
		for (const changed of [
			{ ...context, siteBinding: 'https://other.example.test' },
			{ ...context, view: 'customers' as const },
			{ ...context, filter: 'verified_paid' },
			{ ...context, sort: 'createdAt:asc' as const },
			{ ...context, limit: 50 },
		]) {
			expect(await verifyInspectionCursor(cursor, changed, keys, 90_001)).toBeNull();
		}
	});

	it('rejects tampered, expired, malformed and retired-key cursors', async () => {
		const cursor = await signInspectionCursor('host-page-2', context, keys, 90_000);
		if (!cursor) throw new Error('Cursor signing failed');
		const last = cursor.at(-1)!;
		expect(await verifyInspectionCursor(`${cursor.slice(0, -1)}${last === '0' ? '1' : '0'}`, context, keys, 90_001)).toBeNull();
		expect(await verifyInspectionCursor(cursor, context, keys, 90_000 + INSPECTION_CURSOR_TTL_MS)).toBeNull();
		expect(await verifyInspectionCursor(`${cursor}!`, context, keys, 90_001)).toBeNull();
		expect(await signInspectionCursor('host-page\n2', context, keys, 90_000)).toBeNull();
		expect(await verifyInspectionCursor(cursor, context, { activeKeyId: 'identity-2', keys: [createIndexHmacKey('identity-2', new Uint8Array(32).fill(8))] }, 90_001)).toBeNull();
	});

	it('verifies older key versions during an explicit rotation overlap', async () => {
		const oldKey = createIndexHmacKey('identity-1', new Uint8Array(32).fill(7));
		const cursor = await signInspectionCursor('host-page-2', context, { activeKeyId: oldKey.keyId, keys: [oldKey] }, 90_000);
		const rotated = {
			activeKeyId: 'identity-2',
			keys: [createIndexHmacKey('identity-2', new Uint8Array(32).fill(8)), oldKey],
		};
		expect(await verifyInspectionCursor(cursor, context, rotated, 90_001)).toBe('host-page-2');
	});
});
