import { describe, expect, it } from 'vite-plus/test';
import {
	deriveInitialAttemptId,
	deriveIntentId,
	deriveProtectedIntentFingerprint,
	deriveSuccessorAttemptId,
} from '../../src/domain/intent.js';
import { reserveRequestKey, type RequestKeyRecord, type RequestKeyReservationRequest } from '../../src/storage/request-keys.js';
import { createIndexHmacKey } from '../../src/security/encryption.js';
import { deriveRequestKeyId } from '../../src/domain/identity.js';
import { deterministicRecordId, type VersionedCollection } from '../../src/storage/schema.js';

const key = createIndexHmacKey('identity-v1', new Uint8Array(32).fill(19));
const identity = {
	siteId: 'site_01',
	subject: { kind: 'member' as const, id: 'member_01' },
	merchantId: 'merchant_account_01',
	environment: 'test' as const,
	businessReference: 'order_01',
};
const details = {
	formId: 'form_01',
	formRevision: 'rev_01',
	pricingMode: 'fixed' as const,
	amountMinor: '5000',
	fields: { email: 'payer@example.test', accepted: true },
	metadata: { 'site.order': 'order-01' },
	method: 'card' as const,
	returnPolicy: 'site-default',
};

function reservation(overrides: Partial<RequestKeyReservationRequest> = {}): RequestKeyReservationRequest {
	return {
		identity,
		requestKey: 'request_key_01',
		fingerprint: details,
		nowMs: Date.UTC(2026, 9, 18, 8, 0, 0),
		...overrides,
	};
}

class MemoryRequestKeyCollection implements VersionedCollection<RequestKeyRecord> {
	readonly records = new Map<string, { value: RequestKeyRecord; revision: string }>();
	casCalls = 0;
	deleteCalls = 0;
	throwAfterCommit = false;
	throwBeforeCommit = false;

	async getVersioned(id: string): Promise<{ value: RequestKeyRecord; revision: string } | null> {
	const found = this.records.get(id);
	return found ? structuredClone(found) : null;
	}

	async compareAndSet(
		id: string,
		expectedRevision: string | null,
		data: RequestKeyRecord,
	): Promise<{ applied: true; revision: string } | { applied: false }> {
		this.casCalls += 1;
		if (this.throwBeforeCommit) {
			this.throwBeforeCommit = false;
			throw new Error('unknown bridge result before fixture write');
		}
		const current = this.records.get(id);
		if (expectedRevision === null ? current !== undefined : current?.revision !== expectedRevision) return { applied: false };
		const revision = String((Number(current?.revision ?? '0') + 1));
		this.records.set(id, { value: structuredClone(data), revision });
		if (this.throwAfterCommit) {
			this.throwAfterCommit = false;
			throw new Error('unknown bridge result after fixture write');
		}
		return { applied: true, revision };
	}

	async compareAndDelete(): Promise<{ applied: boolean }> {
		this.deleteCalls += 1;
		return { applied: false };
	}

	async query(): Promise<{ items: Array<{ id: string; data: RequestKeyRecord }>; hasMore: boolean }> {
	return { items: [], hasMore: false };
	}
}

async function storageId(requestKey = 'request_key_01', siteId = identity.siteId): Promise<string> {
	return deterministicRecordId('request_keys', await deriveRequestKeyId(siteId, requestKey, key));
}

describe('canonical intent and permanent request-key reservation', () => {
	it('keeps the intent ID stable across credential/profile version changes and opaque to business identifiers', async () => {
		const base = await deriveIntentId(identity, key);
		const rotated = await deriveIntentId({ ...identity, profileId: 'profile-v8', credentialVersion: 'credential-v12' } as typeof identity, key);
		expect(rotated).toBe(base);
		expect(base).toMatch(/^psk:v1:intents:[a-f0-9]{64}$/u);
		expect(base).not.toContain(identity.subject.id);
		expect(base).not.toContain(identity.businessReference);
	});

	it('canonicalizes only protected details and excludes request keys and retry controls', async () => {
		const identityFingerprint = await deriveProtectedIntentFingerprint(identity, details, key);
		const withTransportControls = await deriveProtectedIntentFingerprint(identity, {
			...details,
			fields: { accepted: true, email: 'payer@example.test' },
			requestKey: 'another-key',
			retryOfAttemptId: 'psk:v1:attempts:' + 'a'.repeat(64),
		} as typeof details, key);
		expect(withTransportControls).toBe(identityFingerprint);
		expect(await deriveProtectedIntentFingerprint(identity, { ...details, amountMinor: '5001' }, key)).not.toBe(identityFingerprint);
		expect(await deriveProtectedIntentFingerprint({ ...identity, businessReference: 'order_02' }, details, key)).not.toBe(identityFingerprint);
	});

	it('rejects malformed runtime field and metadata shapes plus oversized transport keys', async () => {
		await expect(deriveProtectedIntentFingerprint(identity, {
			...details,
			fields: { 'bad-field': 'value' },
		} as unknown as typeof details, key)).rejects.toThrow('INVALID_FINGERPRINT');
		await expect(deriveProtectedIntentFingerprint(identity, {
			...details,
			fields: { email: { nested: true } },
		} as unknown as typeof details, key)).rejects.toThrow('INVALID_FINGERPRINT');
		await expect(deriveProtectedIntentFingerprint(identity, {
			...details,
			metadata: { unnamespaced: 'value' },
		} as unknown as typeof details, key)).rejects.toThrow('INVALID_FINGERPRINT');
		await expect(reserveRequestKey(new MemoryRequestKeyCollection(), reservation({ requestKey: 'k'.repeat(256) }), key))
			.rejects.toThrow('INVALID_REQUEST_KEY');
		await expect(reserveRequestKey(new MemoryRequestKeyCollection(), reservation({ requestKey: 'bad\u0000key' }), key))
			.rejects.toThrow('INVALID_REQUEST_KEY');
	});

	it('derives deterministic initial and predecessor-bound successor attempt IDs within the attempt cap', async () => {
		const intentId = await deriveIntentId(identity, key);
		const initial = await deriveInitialAttemptId(intentId, key);
		expect(await deriveInitialAttemptId(intentId, key)).toBe(initial);
		const second = await deriveSuccessorAttemptId(intentId, initial, 2, key);
		expect(await deriveSuccessorAttemptId(intentId, initial, 2, key)).toBe(second);
		expect(second).not.toBe(initial);
		expect(await deriveSuccessorAttemptId(intentId, second, 3, key)).not.toBe(second);
		await expect(deriveSuccessorAttemptId(intentId, initial, 11, key)).rejects.toThrow('ATTEMPT_LIMIT_EXCEEDED');
		await expect(deriveSuccessorAttemptId(intentId, 'raw-attempt-id', 2, key)).rejects.toThrow('INVALID_ATTEMPT_ID');
	});

	it('persists the minimal permanent key binding before any intent aggregate work', async () => {
		const collection = new MemoryRequestKeyCollection();
		const request = reservation();
		const result = await reserveRequestKey(collection, request, key);
		expect(result.kind).toBe('reserved');
		expect(collection.casCalls).toBe(1);
		expect(collection.deleteCalls).toBe(0);
		if (result.kind !== 'reserved') throw new Error('expected a new reservation');
		expect(result.record.stage).toBe('reserved');
		expect(result.record.accepted).toBe(false);
		expect(result.record.predecessorId).toBeNull();
		expect(result.record.attemptId).toBeNull();
		expect(result.record.intendedAttemptId).toBe(await deriveInitialAttemptId(result.record.intentId, key));
		const serialized = JSON.stringify(result.record);
		expect(serialized).not.toContain(request.requestKey);
		expect(serialized).not.toContain(identity.subject.id);
		expect(serialized).not.toContain(identity.businessReference);
	});

	it('replays the exact allocated attempt and applies owner precedence before changed details', async () => {
		const collection = new MemoryRequestKeyCollection();
		const first = await reserveRequestKey(collection, reservation(), key);
		if (first.kind !== 'reserved') throw new Error('expected initial reservation');
		const id = await storageId();
		collection.records.set(id, {
			value: { ...first.record, stage: 'allocated', accepted: true, attemptId: first.record.intendedAttemptId },
		revision: '2',
		});
		const replay = await reserveRequestKey(collection, reservation(), key);
		expect(replay.kind).toBe('replay');
		if (replay.kind !== 'replay') throw new Error('expected bound replay');
		expect(replay.boundAttemptId).toBe(first.record.intendedAttemptId);

		const differentOwner = await reserveRequestKey(collection, reservation({
			identity: { ...identity, subject: { kind: 'member', id: 'member_02' } },
			fingerprint: { ...details, fields: { nested: { invalid: true } } } as unknown as typeof details,
		}), key);
		expect(differentOwner).toEqual({ kind: 'conflict', code: 'request_key_conflict' });
	});

	it('rejects changed fingerprint or predecessor without rebinding the permanent key', async () => {
		const collection = new MemoryRequestKeyCollection();
		const initial = await reserveRequestKey(collection, reservation(), key);
		if (initial.kind !== 'reserved') throw new Error('expected initial reservation');
		const changed = await reserveRequestKey(collection, reservation({ fingerprint: { ...details, amountMinor: '5001' } }), key);
		expect(changed).toEqual({ kind: 'conflict', code: 'request_key_conflict' });

		const intentId = await deriveIntentId(identity, key);
		const predecessor = await deriveInitialAttemptId(intentId, key);
		const retryRequest = reservation({ retry: { predecessorAttemptId: predecessor, successorOrdinal: 2 } });
		const retryOne = await reserveRequestKey(collection, reservation({ ...retryRequest, requestKey: 'retry-key' }), key);
		expect(retryOne.kind).toBe('reserved');
		const changedPredecessor = await reserveRequestKey(collection, reservation({
			requestKey: 'retry-key',
			retry: { predecessorAttemptId: 'psk:v1:attempts:' + 'c'.repeat(64), successorOrdinal: 2 },
		}), key);
		expect(changedPredecessor).toEqual({ kind: 'conflict', code: 'request_key_conflict' });
	});

	it('converges concurrent equal reservations and concurrent retries on deterministic attempts', async () => {
		const collection = new MemoryRequestKeyCollection();
		const concurrent = await Promise.all([
			reserveRequestKey(collection, reservation(), key),
			reserveRequestKey(collection, reservation(), key),
		]);
		expect(concurrent.map((item) => item.kind).sort()).toEqual(['replay', 'reserved']);
		const [freshA, freshB] = await Promise.all([
			reserveRequestKey(collection, reservation({ requestKey: 'fresh-A' }), key),
			reserveRequestKey(collection, reservation({ requestKey: 'fresh-B' }), key),
		]);
		expect(freshA.kind).toBe('reserved');
		expect(freshB.kind).toBe('reserved');
		if (freshA.kind !== 'reserved' || freshB.kind !== 'reserved') throw new Error('expected fresh key reservations');
		expect(freshA.record.intentId).toBe(freshB.record.intentId);
		expect(freshA.record.intendedAttemptId).toBe(freshB.record.intendedAttemptId);
		const intentId = await deriveIntentId(identity, key);
		const predecessor = await deriveInitialAttemptId(intentId, key);
		const [retryA, retryB] = await Promise.all([
			reserveRequestKey(collection, reservation({ requestKey: 'retry-A', retry: { predecessorAttemptId: predecessor, successorOrdinal: 2 } }), key),
			reserveRequestKey(collection, reservation({ requestKey: 'retry-B', retry: { predecessorAttemptId: predecessor, successorOrdinal: 2 } }), key),
		]);
		expect(retryA.kind).toBe('reserved');
		expect(retryB.kind).toBe('reserved');
		if (retryA.kind !== 'reserved' || retryB.kind !== 'reserved') throw new Error('expected separate retry-key reservations');
		expect(retryA.record.intendedAttemptId).toBe(retryB.record.intendedAttemptId);
		expect(retryA.record.predecessorId).toBe(predecessor);
	});

	it('reconciles an ambiguous write by reading once and never reissuing the create', async () => {
		const collection = new MemoryRequestKeyCollection();
		collection.throwAfterCommit = true;
		const result = await reserveRequestKey(collection, reservation(), key);
		expect(result.kind).toBe('replay');
		expect(collection.casCalls).toBe(1);

		const unavailable = new MemoryRequestKeyCollection();
		unavailable.throwBeforeCommit = true;
		const unknown = await reserveRequestKey(unavailable, reservation(), key);
		expect(unknown).toEqual({ kind: 'unknown' });
		expect(unavailable.casCalls).toBe(1);
		expect(unavailable.records.size).toBe(0);
	});
});
