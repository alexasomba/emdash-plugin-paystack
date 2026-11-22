import { handlePaystackWebhook } from '../../src/routes/webhook.js';
import { encodeBase64Url } from '../../src/security/encryption.js';
import type { ModelRecord } from '../../src/storage/schema.js';

export const PROFILE = 'merchant_profile_1';
export const OLD_SECRET = 'sk_test_old_fixture';
export const CURRENT_SECRET = 'sk_test_current_fixture';
const IDENTITY_KEY = new Uint8Array(32).fill(5);
const FIELD_KEY = new Uint8Array(32).fill(4);
export const URL = 'https://cms.example/api/plugins/paystack-payments/provider/webhook';

export class MemoryInbox {
	readonly entries = new Map<string, ModelRecord>();
	reads = 0;
	writes = 0;
	writeThenThrow = false;
	throwRead = false;

	async getVersioned(id: string) {
		this.reads += 1;
		if (this.throwRead) throw new Error('storage failed');
		const value = this.entries.get(id);
		return value ? { value, revision: 'rev-1' } : null;
	}

	async compareAndSet(id: string, expectedRevision: string | null, value: unknown) {
		this.writes += 1;
		if (this.writeThenThrow) {
			this.entries.set(id, value as ModelRecord);
			throw new Error('write response lost');
		}
		if (expectedRevision !== null || this.entries.has(id)) return { applied: false as const };
		this.entries.set(id, value as ModelRecord);
		return { applied: true as const, revision: 'rev-1' };
	}
}

export class MemoryIntents {
	constructor(private readonly item: ModelRecord | null = null) {}
	async getVersioned(id: string) {
		return this.item && id === this.item.identityHmac ? { value: this.item, revision: 'intent-r1' } : null;
	}
}

export function configuration(versions = [
	{ version: 1, environment: 'test' as const, secretKey: OLD_SECRET },
	{ version: 2, environment: 'test' as const, secretKey: CURRENT_SECRET },
]) {
	return JSON.stringify({
		schemaVersion: 1,
		paused: false,
		activeProfile: PROFILE,
		profiles: {
			[PROFILE]: { profileId: PROFILE, activeCredentialVersion: versions.at(-1)?.version ?? 1, credentialVersions: versions },
			other_profile: { profileId: 'other_profile', activeCredentialVersion: 1, credentialVersions: [{ version: 1, environment: 'test', secretKey: 'sk_test_other_fixture' }] },
		},
		integrationKeys: [],
		fieldEncryptionKeyRing: { activeKeyId: 'field-v1', keys: [{ keyId: 'field-v1', material: encodeBase64Url(FIELD_KEY) }] },
		identityHmacKeyRing: { activeKeyId: 'identity-v1', keys: [{ keyId: 'identity-v1', material: encodeBase64Url(IDENTITY_KEY) }] },
	});
}

export function dependencies(options: { setting?: string; inbox?: MemoryInbox; intents?: MemoryIntents } = {}) {
	const inbox = options.inbox ?? new MemoryInbox();
	const intents = options.intents ?? new MemoryIntents();
	const settings = {
		reads: 0,
		async getVersioned<T>(key: string) {
			this.reads += 1;
			return key === 'paymentConfiguration'
				? { value: (options.setting ?? configuration()) as T, revision: 'settings-1' }
				: null;
		},
	};
	return { inbox, settings, value: { settings, inbox, intents, now: () => Date.parse('2026-10-18T10:00:00.000Z') } };
}

export async function signature(raw: Uint8Array, secret: string): Promise<string> {
	const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']);
	const digest = new Uint8Array(await crypto.subtle.sign('HMAC', key, toArrayBuffer(raw)));
	return [...digest].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export async function send(raw: Uint8Array, secret = CURRENT_SECRET, deps = dependencies()) {
	const signatureHex = await signature(raw, secret);
	const response = await handlePaystackWebhook(raw, {
		method: 'POST', url: URL, headers: { 'x-paystack-signature': signatureHex },
	}, deps.value);
	return { response, deps };
}

export function eventBytes(extra = '"status":"success"', spacing = ''): Uint8Array {
	return new TextEncoder().encode(`{${spacing}"event":"charge.success",${spacing}"data":{${spacing}"reference":"psk-${'a'.repeat(40)}",${spacing}${extra},"id":4045667488,"email":"private@example.test","authorization":{"bin":"411111"}}${spacing}}`);
}
