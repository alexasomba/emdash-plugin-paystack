import { describe, expect, it } from 'vite-plus/test';
import {
	handleConfiguration,
	MAX_CREDENTIAL_VERSIONS_PER_PROFILE,
	MAX_CONFIGURATION_BYTES,
	PAYMENT_CONFIGURATION_SETTING,
	type SettingsPort,
	type VersionedSetting,
} from '../../src/domain/configuration.js';

class MemorySettings implements SettingsPort {
	value: unknown = null;
	revision: string | null = null;
	readonly writes: Array<{ key: string; expectedRevision: string | null; value: unknown }> = [];
	readonly reads: string[] = [];
	conflictNext = false;
	throwRead = false;

	async getVersioned<T>(key: string): Promise<VersionedSetting<T> | null> {
		this.reads.push(key);
		if (this.throwRead) throw new Error('key unavailable');
		return this.revision === null ? null : { value: this.value as T, revision: this.revision };
	}

	async compareAndSet(key: string, expectedRevision: string | null, value: unknown) {
		this.writes.push({ key, expectedRevision, value });
		if (this.conflictNext || expectedRevision !== this.revision) {
			this.conflictNext = false;
			return { applied: false as const };
		}
		this.value = value;
		this.revision = this.revision === null ? 'rev-1' : `rev-${Number(this.revision.slice(4)) + 1}`;
		return { applied: true as const, revision: this.revision };
	}
}

function keyBytes(seed: number): Uint8Array {
	return Uint8Array.from({ length: 32 }, (_, index) => (seed + index + 1) % 256);
}

function makeDependencies(settings = new MemorySettings()) {
	let keySeed = 1;
	const requests: Array<{ url: string; method: string; authorization: string | null }> = [];
	return {
		settings,
		requests,
		dependencies: {
			settings,
			randomBytes: (length: number) => {
				if (length !== 32) throw new Error('unexpected randomness size');
				return keyBytes(keySeed++);
			},
			fetch: async (url: string, init?: RequestInit) => {
				const headers = new Headers(init?.headers);
				requests.push({ url, method: init?.method ?? 'GET', authorization: headers.get('authorization') });
				return new Response(JSON.stringify({ status: true, data: { payment_session_timeout: 3600 } }), {
					status: 200,
					headers: { 'content-type': 'application/json' },
				});
			},
		},
	};
}

async function saveTestProfile(dependencies: ReturnType<typeof makeDependencies>['dependencies'], expectedRevision: string | null = null) {
	return handleConfiguration({
		action: 'save',
		environment: 'test',
		merchantProfile: 'ng-test',
		credentials: { secretKey: 'sk_test_fixture-secret' },
		expectedRevision,
	}, dependencies);
}

describe('revisioned secret configuration implementation', () => {
	it('TC-CFG-IMPL-001 reads an absent setting as paused and unconfigured without provider I/O', async () => {
		const { dependencies, requests, settings } = makeDependencies();
		const result = await handleConfiguration({ action: 'read' }, dependencies);
		expect(result).toEqual({ ok: true, value: { configured: false, paused: true, health: 'unconfigured', revision: null } });
		expect(settings.reads).toEqual([PAYMENT_CONFIGURATION_SETTING]);
		expect(settings.writes).toHaveLength(0);
		expect(requests).toHaveLength(0);
	});

	it('TC-CFG-IMPL-002 writes one bounded JSON string by create-only CAS and never returns secret material', async () => {
		const { dependencies, settings } = makeDependencies();
		const result = await saveTestProfile(dependencies);
		expect(result).toEqual({ ok: true, value: {
			environment: 'test', merchantProfile: 'ng-test', paused: true, configured: true, health: 'ready', revision: 'rev-1',
		} });
		expect(settings.writes).toHaveLength(1);
		expect(settings.writes[0]).toMatchObject({ key: 'paymentConfiguration', expectedRevision: null });
		expect(typeof settings.writes[0]?.value).toBe('string');
		const serialized = settings.writes[0]?.value as string;
		expect(new TextEncoder().encode(serialized).byteLength).toBeLessThanOrEqual(MAX_CONFIGURATION_BYTES);
		const stored = JSON.parse(serialized) as Record<string, unknown>;
		expect(stored.schemaVersion).toBe(1);
		expect(stored.paused).toBe(true);
		expect(JSON.stringify(result)).not.toContain('fixture-secret');
		expect(JSON.stringify(result)).not.toContain('fieldEncryptionKeyRing');
		expect(JSON.stringify(result)).not.toContain('identityHmacKeyRing');
	});

	it('TC-CFG-IMPL-003 preserves absent secrets and appends an immutable credential version', async () => {
		const { dependencies, settings } = makeDependencies();
		await saveTestProfile(dependencies);
		const firstWrite = settings.writes[0]?.value as string;
		const result = await handleConfiguration({
			action: 'save', environment: 'test', merchantProfile: 'ng-test', expectedRevision: 'rev-1',
		}, dependencies);
		expect(result).toMatchObject({ ok: true, value: { revision: 'rev-2', configured: true, paused: true } });
		const secondWrite = settings.writes[1]?.value as string;
		const before = JSON.parse(firstWrite) as { profiles: Record<string, { credentialVersions: unknown[] }> };
		const after = JSON.parse(secondWrite) as { profiles: Record<string, { activeCredentialVersion: number; credentialVersions: Array<{ version: number; secretKey: string }> }> };
		expect(before.profiles['ng-test']?.credentialVersions).toHaveLength(1);
		expect(after.profiles['ng-test']?.credentialVersions).toEqual([
			{ version: 1, environment: 'test', secretKey: 'sk_test_fixture-secret' },
			{ version: 2, environment: 'test', secretKey: 'sk_test_fixture-secret' },
		]);
		expect(after.profiles['ng-test']?.activeCredentialVersion).toBe(2);
	});

	it('TC-CFG-IMPL-004 rejects environment/key mismatch and unsupported object-secret writes', async () => {
		const { dependencies, settings, requests } = makeDependencies();
		const mismatch = await handleConfiguration({
			action: 'save', environment: 'live', merchantProfile: 'ng-live',
			credentials: { secretKey: 'sk_test_wrong-environment' }, expectedRevision: null,
		}, dependencies);
		expect(mismatch).toMatchObject({ ok: false, error: { code: 'validation_error' } });
		expect(settings.writes).toHaveLength(0);
		settings.value = { secretKey: 'plaintext-object-must-not-be-used' };
		settings.revision = 'rev-1';
		const objectRead = await handleConfiguration({ action: 'read' }, dependencies);
		expect(objectRead).toMatchObject({ ok: false, error: { code: 'storage_unavailable' } });
		expect(requests).toHaveLength(0);
	});

	it('TC-CFG-IMPL-005 returns stale_revision for stale save and pause without any retry or provider request', async () => {
		const { dependencies, settings, requests } = makeDependencies();
		await saveTestProfile(dependencies);
		const save = await handleConfiguration({
			action: 'save', environment: 'test', merchantProfile: 'ng-test',
			credentials: { secretKey: 'sk_test_other-secret' }, expectedRevision: 'stale-rev',
		}, dependencies);
		const pause = await handleConfiguration({ action: 'pause', paused: false, expectedRevision: 'stale-rev' }, dependencies);
		expect(save).toMatchObject({ ok: false, error: { code: 'stale_revision' } });
		expect(pause).toMatchObject({ ok: false, error: { code: 'stale_revision' } });
		expect(settings.writes).toHaveLength(1);
		expect(requests).toHaveLength(0);
	});

	it('TC-CFG-IMPL-006 treats host key/decryption failures as unavailable without plaintext fallback', async () => {
		const { dependencies, settings } = makeDependencies();
		settings.revision = 'rev-1';
		settings.value = 'unreadable host-encrypted value';
		settings.throwRead = true;
		const result = await handleConfiguration({ action: 'read' }, dependencies);
		expect(result).toMatchObject({ ok: false, error: { code: 'storage_unavailable' } });
		expect(settings.writes).toHaveLength(0);
	});

	it('TC-CFG-IMPL-007 health performs only the read-only Paystack integration GET and returns a finite safe category', async () => {
		const { dependencies, settings, requests } = makeDependencies();
		await saveTestProfile(dependencies);
		const health = await handleConfiguration({ action: 'health' }, dependencies);
		expect(health).toEqual({ ok: true, value: {
			environment: 'test', merchantProfile: 'ng-test', paused: true, configured: true, health: 'ready', revision: 'rev-1',
		} });
		expect(requests).toEqual([{
			url: 'https://api.paystack.co/integration/payment_session_timeout',
			method: 'GET',
			authorization: 'Bearer sk_test_fixture-secret',
		}]);
		expect(settings.writes).toHaveLength(1);
		expect(JSON.stringify(health)).not.toContain('fixture-secret');
	});

	it('TC-CFG-IMPL-008 rejects invalid or oversized persisted configuration instead of repairing it', async () => {
		const { dependencies, settings } = makeDependencies();
		settings.revision = 'rev-1';
		settings.value = JSON.stringify({ schemaVersion: 99, secretKey: 'sk_test_not-a-versioned-config' });
		const unknownVersion = await handleConfiguration({ action: 'read' }, dependencies);
		expect(unknownVersion).toMatchObject({ ok: false, error: { code: 'storage_unavailable' } });
		settings.value = ' '.repeat(MAX_CONFIGURATION_BYTES + 1);
		const oversized = await handleConfiguration({ action: 'read' }, dependencies);
		expect(oversized).toMatchObject({ ok: false, error: { code: 'storage_unavailable' } });
		expect(settings.writes).toHaveLength(0);
	});

	it('TC-CFG-IMPL-009 generates distinct purpose-separated key rings and retains both on later revisions', async () => {
		const { dependencies, settings } = makeDependencies();
		await saveTestProfile(dependencies);
		const initial = JSON.parse(settings.writes[0]?.value as string) as {
			fieldEncryptionKeyRing: { keys: Array<{ material: string }> };
			identityHmacKeyRing: { keys: Array<{ material: string }> };
		};
		expect(initial.fieldEncryptionKeyRing.keys[0]?.material).not.toBe(initial.identityHmacKeyRing.keys[0]?.material);
		await handleConfiguration({ action: 'pause', paused: true, expectedRevision: 'rev-1' }, dependencies);
		const updated = JSON.parse(settings.writes[1]?.value as string) as typeof initial;
		expect(updated.fieldEncryptionKeyRing).toEqual(initial.fieldEncryptionKeyRing);
		expect(updated.identityHmacKeyRing).toEqual(initial.identityHmacKeyRing);
	});

	it('TC-CFG-IMPL-010 surfaces a compare-and-set race without retrying or replacing the winner', async () => {
		const { dependencies, settings } = makeDependencies();
		await saveTestProfile(dependencies);
		const winner = settings.writes[0]?.value;
		settings.conflictNext = true;
		const result = await handleConfiguration({
			action: 'save', environment: 'test', merchantProfile: 'ng-test',
			credentials: { secretKey: 'sk_test_losing-update' }, expectedRevision: 'rev-1',
		}, dependencies);
		expect(result).toMatchObject({ ok: false, error: { code: 'stale_revision' } });
		expect(settings.writes).toHaveLength(2);
		expect(settings.value).toBe(winner);
		expect(settings.revision).toBe('rev-1');
	});

	it('TC-CFG-IMPL-011 refuses another credential version when webhook verification reaches its fixed bound', async () => {
		const { dependencies, settings } = makeDependencies();
		await saveTestProfile(dependencies);
		const stored = JSON.parse(settings.writes[0]?.value as string) as {
			profiles: Record<string, { activeCredentialVersion: number; credentialVersions: Array<{ version: number; environment: string; secretKey: string }> }>;
		};
		const profile = stored.profiles['ng-test'];
		if (!profile) throw new Error('Missing configured profile');
		while (profile.credentialVersions.length < MAX_CREDENTIAL_VERSIONS_PER_PROFILE) {
			const version = profile.credentialVersions.length + 1;
			profile.credentialVersions.push({ version, environment: 'test', secretKey: 'sk_test_fixture-secret' });
		}
		profile.activeCredentialVersion = MAX_CREDENTIAL_VERSIONS_PER_PROFILE;
		settings.value = JSON.stringify(stored);

		const result = await handleConfiguration({
			action: 'save', environment: 'test', merchantProfile: 'ng-test', expectedRevision: 'rev-1',
		}, dependencies);
		expect(result).toMatchObject({ ok: false, error: { code: 'review_required' } });
		expect(settings.writes).toHaveLength(1);
	});
});
