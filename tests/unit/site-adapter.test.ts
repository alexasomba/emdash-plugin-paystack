import { describe, expect, it, vi } from 'vite-plus/test';
import { authenticateSiteRequest, type SiteAuthDependencies } from '../../examples/astro-site/server-adapter/auth.js';
import { createPaystackSiteAdapter } from '../../examples/astro-site/server-adapter/index.js';
import { createPersistentRateLimiter } from '../../examples/astro-site/server-adapter/rate-limit.js';
import {
	assignBusinessIntent,
	canSubmitIntent,
	DEFAULT_ADMISSION_ROLLOUT,
	identityKeyFingerprint,
	isGuardedAdmissionRolloutState,
	promoteAdmission,
	restoreAdmissionRolloutState,
	type PromotionEvidence,
} from '../../examples/astro-site/server-adapter/rollout.js';
import { createPersistentPaymentStore, type PersistentSqlDatabase, type PersistentSqlStatement } from '../../examples/astro-site/server-adapter/persistent-store.js';
import type { PersistentPaymentStore } from '../../examples/astro-site/server-adapter/persistent-store.js';
import { verifySiteAttestation, type SiteAttestationKey } from '../../src/security/attestation.js';
import { parseStrictJson } from '../../src/security/json.js';

const principal = { transport: 'session' as const, siteId: 'site-one', subject: { kind: 'member' as const, id: 'member-7' } };
const runtimeBridgeMock = vi.hoisted(() => ({ withEmDashRuntime: vi.fn(), calls: [] as unknown[][] }));
vi.mock('emdash/middleware', () => ({ withEmDashRuntime: runtimeBridgeMock.withEmDashRuntime }));

describe('server site authentication', () => {
	it('requires the exact consuming-site origin, site-owned identity and CSRF verification', async () => {
		const verifyCsrf = vi.fn(async () => true);
		const dependencies: SiteAuthDependencies = {
			siteOrigin: 'https://shop.example',
			resolveSession: async () => principal,
			resolveGuestCapability: async () => null,
			verifyCsrf,
		};
		const accepted = await authenticateSiteRequest(
			new Request('https://shop.example/api/payment/submit', {
				method: 'POST', headers: { origin: 'https://shop.example', 'x-csrf-token': 'opaque' },
			}),
			'submit', 'site-one', dependencies, 1_000,
		);
		expect(accepted).toEqual({ ok: true, principal });
		expect(verifyCsrf).toHaveBeenCalledOnce();

		const wrongOrigin = await authenticateSiteRequest(
			new Request('https://shop.example/api/payment/submit', { method: 'POST', headers: { origin: 'https://evil.example' } }),
			'submit', 'site-one', dependencies, 1_000,
		);
		expect(wrongOrigin).toMatchObject({ ok: false, status: 403 });
		expect(verifyCsrf).toHaveBeenCalledOnce();
	});

	it('requires an unexpired guest capability bound to the requested operation', async () => {
		const dependencies: SiteAuthDependencies = {
			siteOrigin: 'https://shop.example',
			resolveSession: async () => null,
			resolveGuestCapability: async () => ({
				transport: 'guest_capability', siteId: 'site-one', subject: { kind: 'guest', id: 'guest-1' },
				expiresAtMs: 5_000, allowedOperations: ['status'],
			}),
			verifyCsrf: async () => true,
		};
		const request = () => new Request('https://shop.example/api/payment/submit', {
			method: 'POST', headers: { origin: 'https://shop.example', authorization: `Bearer ${'c'.repeat(24)}` },
		});
		expect(await authenticateSiteRequest(request(), 'submit', 'site-one', dependencies, 1_000))
			.toMatchObject({ ok: false, status: 401 });
		expect(await authenticateSiteRequest(request(), 'status', 'site-one', dependencies, 5_000))
			.toMatchObject({ ok: false, status: 401 });
	});
});

describe('durable rate limits', () => {
	it('enforces mutation, status, feed, ACK, and public-render scopes at their approved limits', async () => {
		const counts = new Map<string, { windowStartMs: number; count: number }>();
		const store: PersistentPaymentStore = {
			durable: true,
			ensureReady: async () => {},
			async consumeWindow(key, windowStartMs) {
				const row = counts.get(key);
				if (!row || row.windowStartMs < windowStartMs) {
					counts.set(key, { windowStartMs, count: 1 });
					return 1;
				}
				row.count += 1;
				return row.count;
			},
			async bindIdentityKeyFingerprint() { return true; },
			async getOrCreateCohort(_key, bucket) { return bucket; },
		};
		const limiter = createPersistentRateLimiter(store);
		const call = (quota: 'mutation' | 'status' | 'feed' | 'ack' | 'public_render_ip' | 'public_render_site', subjectPartition = 'a'.repeat(64)) =>
			limiter.consume({ quota, sitePartition: 'b'.repeat(64), subjectPartition, nowMs: 60_000 });

		for (let attempt = 0; attempt < 10; attempt += 1) expect((await call('mutation')).allowed).toBe(true);
		expect((await call('mutation')).allowed).toBe(false);
		for (let attempt = 0; attempt < 60; attempt += 1) {
			const result = await limiter.consume({
				quota: 'mutation', sitePartition: 'c'.repeat(64), subjectPartition: String(attempt).padStart(64, '0'), nowMs: 120_000,
			});
			expect(result.allowed).toBe(true);
		}
		expect(await limiter.consume({
			quota: 'mutation', sitePartition: 'c'.repeat(64), subjectPartition: 'd'.repeat(64), nowMs: 120_000,
		})).toMatchObject({ allowed: false, exceeded: 'site' });
		for (let attempt = 0; attempt < 30; attempt += 1) expect((await call('status', 'c'.repeat(64))).allowed).toBe(true);
		expect((await call('status', 'c'.repeat(64))).allowed).toBe(false);
		for (let attempt = 0; attempt < 30; attempt += 1) expect((await call('feed', 'd'.repeat(64))).allowed).toBe(true);
		expect((await call('feed', 'd'.repeat(64))).allowed).toBe(false);
		for (let attempt = 0; attempt < 120; attempt += 1) expect((await call('ack', 'e'.repeat(64))).allowed).toBe(true);
		expect((await call('ack', 'e'.repeat(64))).allowed).toBe(false);
		for (let attempt = 0; attempt < 60; attempt += 1) expect((await call('public_render_ip', 'f'.repeat(64))).allowed).toBe(true);
		expect((await call('public_render_ip', 'f'.repeat(64))).allowed).toBe(false);
		for (let attempt = 0; attempt < 300; attempt += 1) {
			expect((await limiter.consume({
				quota: 'public_render_site', sitePartition: '9'.repeat(64),
				subjectPartition: String(attempt).padStart(64, '0'), nowMs: 60_000,
			})).allowed).toBe(true);
		}
		expect(await limiter.consume({
			quota: 'public_render_site', sitePartition: '9'.repeat(64), subjectPartition: '8'.repeat(64), nowMs: 60_000,
		})).toMatchObject({ allowed: false, exceeded: 'site' });
	});
});

describe('admission rollout', () => {
	const evidence: PromotionEvidence = {
		reviewed: true,
		runtimeBudgetsProven: true,
		providerFinalityProven: true,
		releaseApproved: true,
		duplicatePaidResultIdentities: 0,
		ownershipPrivacyViolations: 0,
	};

	it('assigns a stable business-intent cohort and preserves it across adapter recreation', async () => {
		const key = new Uint8Array(32).fill(9);
		const first = await assignBusinessIntent(key, {
			siteId: 'site-one', subject: { kind: 'member', id: 'member-7' }, businessReference: 'order-22',
		});
		const afterRestart = await assignBusinessIntent(key, {
			siteId: 'site-one', subject: { kind: 'member', id: 'member-7' }, businessReference: 'order-22',
		});
		expect(afterRestart).toEqual(first);
		expect(await identityKeyFingerprint(key)).toHaveLength(64);
		expect(await identityKeyFingerprint(new Uint8Array(32).fill(10))).not.toBe(await identityKeyFingerprint(key));
	});

	it('keeps new admission closed by default while existing intents remain actionable', () => {
		expect(DEFAULT_ADMISSION_ROLLOUT).toMatchObject({ admissionEnabled: false, paused: true, percent: 0 });
		expect(canSubmitIntent(DEFAULT_ADMISSION_ROLLOUT, 2_500, false)).toBe(false);
		expect(canSubmitIntent(DEFAULT_ADMISSION_ROLLOUT, 9_999, true)).toBe(true);
		expect(canSubmitIntent({ admissionEnabled: true, paused: false, percent: 1 } as never, 99, false)).toBe(false);
	});

	it('requires sequential manual promotion and complete evidence, including on restore', () => {
		expect(isGuardedAdmissionRolloutState({ admissionEnabled: true, paused: false, percent: 100 })).toBe(false);
		expect(promoteAdmission(DEFAULT_ADMISSION_ROLLOUT, 10, evidence)).toEqual({ ok: false, reason: 'invalid_step' });
		expect(promoteAdmission(DEFAULT_ADMISSION_ROLLOUT, 1, { ...evidence, providerFinalityProven: false }))
			.toEqual({ ok: false, reason: 'gates_incomplete' });
		const first = promoteAdmission(DEFAULT_ADMISSION_ROLLOUT, 1, evidence);
		expect(first.ok).toBe(true);
		if (!first.ok) return;
		expect(isGuardedAdmissionRolloutState(first.state)).toBe(true);
		const second = promoteAdmission(first.state, 10, evidence);
		expect(second.ok).toBe(true);
		const restored = restoreAdmissionRolloutState([{ percent: 1, evidence }, { percent: 10, evidence }]);
		expect(restored?.percent).toBe(10);
		expect(restoreAdmissionRolloutState([{ percent: 10, evidence }])).toBeNull();
	});

	it('uses inclusive deterministic admission boundaries and preserves owned recovery while paused', () => {
		let onePercent = DEFAULT_ADMISSION_ROLLOUT;
		const one = promoteAdmission(onePercent, 1, evidence);
		expect(one.ok).toBe(true);
		if (!one.ok) return;
		onePercent = one.state;
		expect(canSubmitIntent(onePercent, 99, false)).toBe(true);
		expect(canSubmitIntent(onePercent, 100, false)).toBe(false);

		let full = onePercent;
		for (const percent of [10, 50, 100] as const) {
			const next = promoteAdmission(full, percent, evidence);
			expect(next.ok).toBe(true);
			if (!next.ok) return;
			full = next.state;
		}
		expect(canSubmitIntent(full, 9_999, false)).toBe(true);
		expect(canSubmitIntent({ admissionEnabled: false, paused: true, percent: 0 } as never, 9_999, true)).toBe(true);
	});
});

describe('persistent payment store', () => {
	it('retains rate state, key binding, and cohort assignment across store reconstruction', async () => {
		const database = new MemoryD1();
		const first = createPersistentPaymentStore(database);
		expect(await first.consumeWindow('status:subject', 60_000)).toBe(1);
		expect(await first.bindIdentityKeyFingerprint('f'.repeat(64))).toBe(true);
		expect(await first.getOrCreateCohort('e'.repeat(64), 42)).toBe(42);

		const afterRestart = createPersistentPaymentStore(database);
		expect(await afterRestart.consumeWindow('status:subject', 60_000)).toBe(2);
		expect(await afterRestart.bindIdentityKeyFingerprint('f'.repeat(64))).toBe(true);
		expect(await afterRestart.bindIdentityKeyFingerprint('a'.repeat(64))).toBe(false);
		expect(await afterRestart.getOrCreateCohort('e'.repeat(64), 9_999)).toBe(42);
	});
});

describe('site adapter refusal boundary', () => {
	it('fails before resolution, signing, or runtime invocation when the persistent limiter is absent', async () => {
		const resolveSubmitContext = vi.fn(async () => null);
		const adapter = createPaystackSiteAdapter({
			installedPluginId: 'did-plc-plugin', siteId: 'site-one', keyId: 'key-1',
			siteAttestationKey: new Uint8Array(32).fill(1), identityHmacKey: new Uint8Array(32).fill(2),
			resolveSubmitContext,
			resolveOwnedContext: async () => null,
		});
		const response = await adapter.submit(new Request('https://shop.example/payment/submit', {
			method: 'POST', headers: { origin: 'https://shop.example', 'content-type': 'application/json' },
			body: JSON.stringify({ schemaVersion: '1.0' }),
		}));
		expect(response.status).toBe(503);
		expect(resolveSubmitContext).not.toHaveBeenCalled();
	});

	it('rejects browser rollout and trusted-identity claims before resolving an order', async () => {
		const store = testStore();
		const resolveSubmitContext = vi.fn(async () => null);
		const adapter = createPaystackSiteAdapter({
			installedPluginId: 'did-plc-plugin', siteId: 'site-one', keyId: 'key-1',
			siteAttestationKey: new Uint8Array(32).fill(1), identityHmacKey: new Uint8Array(32).fill(2),
			store, limiter: createPersistentRateLimiter(store),
			auth: {
				siteOrigin: 'https://shop.example',
				resolveSession: async () => principal,
				resolveGuestCapability: async () => null,
				verifyCsrf: async () => true,
			},
			resolveSubmitContext,
			resolveOwnedContext: async () => null,
		});
		const response = await adapter.submit(new Request('https://shop.example/payment/submit', {
			method: 'POST',
			headers: { origin: 'https://shop.example', 'content-type': 'application/json' },
			body: JSON.stringify({
				schemaVersion: '1.0', formId: 'form-1', formRevision: 'rev-1', requestKey: 'request-1', fields: {},
				siteId: 'forged-site', subject: { kind: 'member', id: 'attacker' }, businessReference: 'forged-order',
				admissionEnabled: true, percent: 100,
			}),
		}));
		expect(response.status).toBe(400);
		expect(resolveSubmitContext).not.toHaveBeenCalled();
	});

	it('rejects an arbitrary rollout object and keeps a new intent closed', async () => {
		const store = testStore();
		const resolveSubmitContext = vi.fn(async () => ({
			merchantProfile: 'merchant-1', businessReference: 'order-1', publishedFormRevision: 'rev-1',
			pricingMode: 'fixed' as const, existingIntent: false,
		}));
		const adapter = createPaystackSiteAdapter({
			installedPluginId: 'did-plc-plugin', siteId: 'site-one', keyId: 'key-1',
			siteAttestationKey: new Uint8Array(32).fill(1), identityHmacKey: new Uint8Array(32).fill(2),
			store, limiter: createPersistentRateLimiter(store),
			rollout: { admissionEnabled: true, paused: false, percent: 100 } as never,
			auth: {
				siteOrigin: 'https://shop.example',
				resolveSession: async () => principal,
				resolveGuestCapability: async () => null,
				verifyCsrf: async () => true,
			},
			resolveSubmitContext,
			resolveOwnedContext: async () => null,
		});
		const response = await adapter.submit(new Request('https://shop.example/payment/submit', {
			method: 'POST',
			headers: { origin: 'https://shop.example', 'content-type': 'application/json' },
			body: JSON.stringify({ schemaVersion: '1.0', formId: 'form-1', formRevision: 'rev-1', requestKey: 'request-1', fields: {} }),
		}));
		expect(response.status).toBe(409);
		expect(resolveSubmitContext).toHaveBeenCalledOnce();
	});

	it('refuses an owned-status resolver result bound to a different site or subject before raw invocation', async () => {
		const store = testStore();
		runtimeBridgeMock.calls.splice(0);
		const intentId = `psk:v1:intents:${'e'.repeat(64)}`;
		const adapter = createPaystackSiteAdapter({
			installedPluginId: 'did-plc-plugin', siteId: 'site-one', keyId: 'key-1',
			siteAttestationKey: new Uint8Array(32).fill(1), identityHmacKey: new Uint8Array(32).fill(2),
			store, limiter: createPersistentRateLimiter(store),
			auth: {
				siteOrigin: 'https://shop.example', resolveSession: async () => principal,
				resolveGuestCapability: async () => null, verifyCsrf: async () => true,
			},
			resolveSubmitContext: async () => null,
			resolveOwnedContext: async () => ({
				siteId: 'site-one', subject: { kind: 'member', id: 'another-member' },
				intentId, merchantProfile: 'merchant-1',
			}),
	});
		const response = await adapter.status(new Request('https://shop.example/payment/status', {
			method: 'POST', headers: { origin: 'https://shop.example', 'content-type': 'application/json' },
			body: JSON.stringify({ schemaVersion: '1.0', intentId }),
		}));
		expect(response.status).toBe(403);
		expect(runtimeBridgeMock.calls).toHaveLength(0);
	});

	it('forwards the authenticated intentId in the exact private action envelope', async () => {
		const store = testStore();
		const siteKey = new Uint8Array(32).fill(31);
		const attemptId = 'psk:v1:attempts:' + 'a'.repeat(64);
		const intentId = 'psk:v1:intents:' + 'b'.repeat(64);
		runtimeBridgeMock.calls.splice(0);
		runtimeBridgeMock.withEmDashRuntime.mockImplementationOnce(async (run: (runtime: unknown) => Promise<unknown>) => {
			const runtime = {
				handlePluginApiRoute: async (...args: unknown[]) => {
					runtimeBridgeMock.calls.push(args);
					return { success: true, data: { ok: true, value: {
						schemaVersion: '1.0', intentId, attemptId, state: 'requires_action',
						deliveryState: 'not_eligible',
						nextAction: { id: attemptId, kind: 'redirect', destination: 'https://checkout.paystack.com/checkout_1' },
					} } };
				},
			};
			return run(runtime);
		});
		const adapter = createPaystackSiteAdapter({
			installedPluginId: 'did-plc-plugin', siteId: 'site-one', keyId: 'key-1',
			siteAttestationKey: siteKey, identityHmacKey: new Uint8Array(32).fill(32),
			store, limiter: createPersistentRateLimiter(store), now: () => 120_000,
			auth: {
				siteOrigin: 'https://shop.example', resolveSession: async () => principal,
				resolveGuestCapability: async () => null, verifyCsrf: async () => true,
			},
			resolveSubmitContext: async () => null,
			resolveOwnedContext: async ({ operation, principal: authenticated, intentId: requestedIntentId, attemptId: requestedAttemptId, actionId }) =>
				operation === 'action' && requestedIntentId === intentId && requestedAttemptId === attemptId && actionId === attemptId
					? { siteId: authenticated.siteId, subject: authenticated.subject, intentId, merchantProfile: 'merchant-1', attemptId, actionId,
						callbackUrl: 'https://shop.example/payments/return' }
					: null,
		});

		const response = await adapter.action(new Request('https://shop.example/payment/action', {
			method: 'POST',
			headers: { origin: 'https://shop.example', 'content-type': 'application/json' },
			body: JSON.stringify({ schemaVersion: '1.0', intentId, attemptId, actionId: attemptId }),
		}));
		expect(response.status).toBe(202);
		expect(runtimeBridgeMock.calls).toHaveLength(1);
		const [runtimeId, method, route, signedRequest] = runtimeBridgeMock.calls[0]!;
		expect(runtimeId).toBe('did-plc-plugin');
		expect(method).toBe('POST');
		expect(route).toBe('/payments/action');
		expect(signedRequest).toBeInstanceOf(Request);
		const trustedBody = await (signedRequest as Request).json();
		expect(trustedBody).toEqual({
			schemaVersion: '1.0', siteId: 'site-one', subject: principal.subject,
			merchantProfile: 'merchant-1', intentId, attemptId, actionId: attemptId,
			siteOrigin: 'https://shop.example', callbackUrl: 'https://shop.example/payments/return',
		});
	});

	it('signs exact trusted bytes and invokes only the configured static EmDash route', async () => {
		const store = testStore();
		const siteKey = new Uint8Array(32).fill(3);
		const identityKey = new Uint8Array(32).fill(4);
		let rollout = DEFAULT_ADMISSION_ROLLOUT;
		for (const percent of [1, 10, 50, 100]) {
			const promoted = promoteAdmission(rollout, percent, {
				reviewed: true, runtimeBudgetsProven: true, providerFinalityProven: true, releaseApproved: true,
				duplicatePaidResultIdentities: 0, ownershipPrivacyViolations: 0,
			});
			if (!promoted.ok) throw new Error('Test rollout fixture must pass all gates');
			rollout = promoted.state;
		}
		runtimeBridgeMock.calls.splice(0);
		runtimeBridgeMock.withEmDashRuntime.mockImplementation(async (run: (runtime: unknown) => Promise<unknown>) => {
			const runtime = {
				handlePluginApiRoute: async (...args: unknown[]) => {
					runtimeBridgeMock.calls.push(args);
					return { success: true, data: { ok: true, value: {
						schemaVersion: '1.0', intentId: `psk:v1:intents:${'d'.repeat(64)}`,
						attemptId: `psk:v1:attempts:${'f'.repeat(64)}`, state: 'initializing', deliveryState: 'not_eligible',
					} } };
				},
			};
			return run(runtime);
		});
		const adapter = createPaystackSiteAdapter({
			installedPluginId: 'did-plc-plugin', siteId: 'site-one', keyId: 'key-1',
			siteAttestationKey: siteKey, identityHmacKey: identityKey, store, limiter: createPersistentRateLimiter(store),
			rollout,
			auth: {
				siteOrigin: 'https://shop.example', resolveSession: async () => principal,
				resolveGuestCapability: async () => null, verifyCsrf: async () => true,
			},
			resolveSubmitContext: async () => ({
				merchantProfile: 'merchant-1', businessReference: 'server-order-22', publishedFormRevision: 'rev-1',
				pricingMode: 'trusted_order', resolvedOrderPrice: { currency: 'NGN', value: '1500.00' }, existingIntent: false,
			}),
			resolveOwnedContext: async () => null,
			now: () => 120_000,
		});
		const response = await adapter.submit(new Request('https://shop.example/payment/submit', {
			method: 'POST', headers: { origin: 'https://shop.example', 'content-type': 'application/json' },
			body: JSON.stringify({ schemaVersion: '1.0', formId: 'form-1', formRevision: 'rev-1', requestKey: 'request-1', fields: {} }),
		}));
		expect(response.status).toBe(202);
		expect(runtimeBridgeMock.calls).toHaveLength(1);
		const [runtimeId, method, route, signedRequest] = runtimeBridgeMock.calls[0]!;
		expect(runtimeId).toBe('did-plc-plugin');
		expect(method).toBe('POST');
		expect(route).toBe('/payments/submit');
		expect(signedRequest).toBeInstanceOf(Request);
		const rawRequest = signedRequest as Request;
		const rawBody = new Uint8Array(await rawRequest.arrayBuffer());
		const key: SiteAttestationKey = {
			provider: 'paystack', siteId: 'site-one', keyId: 'key-1', purpose: 'site-payment',
			material: siteKey, state: 'current',
		};
		const verified = await verifySiteAttestation({
			provider: 'paystack', method: String(method), route: 'payments/submit', rawBody,
			headers: {
				'x-payment-site-id': rawRequest.headers.get('x-payment-site-id')!,
				'x-payment-key-id': rawRequest.headers.get('x-payment-key-id')!,
				'x-payment-timestamp': rawRequest.headers.get('x-payment-timestamp')!,
				'x-payment-nonce': rawRequest.headers.get('x-payment-nonce')!,
				'x-payment-signature': rawRequest.headers.get('x-payment-signature')!,
			},
			nowMs: 120_000, keys: [key],
		});
		expect(verified).not.toBeNull();
		const trustedBody = parseStrictJson(rawBody) as Record<string, unknown>;
		expect(trustedBody).toMatchObject({ siteId: 'site-one', businessReference: 'server-order-22', merchantProfile: 'merchant-1' });
		expect(trustedBody.resolvedOrderPrice).toEqual({ currency: 'NGN', value: '1500.00' });
		expect(trustedBody).not.toHaveProperty('identityHmacKey');
		expect(trustedBody).not.toHaveProperty('siteAttestationKey');
	});
});

function testStore(): PersistentPaymentStore {
	const rows = new Map<string, { windowStartMs: number; count: number }>();
	return {
		durable: true,
		ensureReady: async () => {},
		async consumeWindow(key, windowStartMs) {
			const row = rows.get(key);
			if (!row || row.windowStartMs < windowStartMs) {
				rows.set(key, { windowStartMs, count: 1 });
				return 1;
			}
			row.count += 1;
			return row.count;
		},
		async bindIdentityKeyFingerprint() { return true; },
		async getOrCreateCohort(_digest, bucket) { return bucket; },
	};
}

class MemoryD1 implements PersistentSqlDatabase {
	readonly #rate = new Map<string, { windowStartMs: number; count: number }>();
	readonly #identity = new Map<string, string>();
	readonly #cohorts = new Map<string, number>();

	prepare(query: string): PersistentSqlStatement {
		const values: unknown[] = [];
		const normalized = query.replace(/\s+/gu, ' ').trim();
		const statement: PersistentSqlStatement = {
			bind: (...nextValues) => { values.splice(0, values.length, ...nextValues); return statement; },
			async first<T>() {
				if (normalized.startsWith('INSERT INTO emdash_paystack_rate_windows')) {
					const key = String(values[0]);
					const windowStartMs = Number(values[1]);
					const previous = database.#rate.get(key);
					const count = !previous || previous.windowStartMs < windowStartMs ? 1 : previous.count + 1;
					database.#rate.set(key, { windowStartMs: Math.max(previous?.windowStartMs ?? 0, windowStartMs), count });
					return { count } as T;
				}
				if (normalized.startsWith('SELECT fingerprint')) {
					const fingerprint = database.#identity.get('installation-identity-hmac-v1');
					return (fingerprint ? { fingerprint } : null) as T | null;
				}
				if (normalized.startsWith('SELECT bucket')) {
					const bucket = database.#cohorts.get(String(values[0]));
					return (bucket === undefined ? null : { bucket }) as T | null;
				}
				throw new Error(`Unexpected first query: ${normalized}`);
			},
			async run() {
				if (normalized.startsWith('CREATE TABLE')) return { success: true };
				if (normalized.startsWith('INSERT INTO emdash_paystack_identity_key_binding')) {
					if (!database.#identity.has('installation-identity-hmac-v1')) {
						database.#identity.set('installation-identity-hmac-v1', String(values[0]));
					}
					return { success: true };
				}
				if (normalized.startsWith('INSERT INTO emdash_paystack_rollout_cohorts')) {
					const digest = String(values[0]);
					if (!database.#cohorts.has(digest)) database.#cohorts.set(digest, Number(values[1]));
					return { success: true };
				}
				throw new Error(`Unexpected run query: ${normalized}`);
			},
		};
		const database = this;
		return statement;
	}
}
