import { afterEach, beforeEach, describe, expect, it, vi } from 'vite-plus/test';
import { createPluginRuntimeTestHost, type PluginRuntimeTestHost } from '@emdash-cms/plugin-test';
import {
	createPaystackSiteAdapter,
	type PaystackSiteAdapterOptions,
	type TrustedSubmitContext,
} from '../../examples/astro-site/server-adapter/index.js';
import { createPersistentRateLimiter } from '../../examples/astro-site/server-adapter/rate-limit.js';
import {
	DEFAULT_ADMISSION_ROLLOUT,
	promoteAdmission,
	type AdmissionRolloutState,
	type PromotionEvidence,
} from '../../examples/astro-site/server-adapter/rollout.js';
import type { PersistentPaymentStore } from '../../examples/astro-site/server-adapter/persistent-store.js';
import { verifySiteAttestation, type SiteAttestationKey } from '../../src/security/attestation.js';
import { approvedExamples } from '../support/spec-fixtures.js';

const runtimeBridge = vi.hoisted(() => ({ withEmDashRuntime: vi.fn() }));
vi.mock('emdash/middleware', () => ({ withEmDashRuntime: runtimeBridge.withEmDashRuntime }));

let host: PluginRuntimeTestHost;

const evidence: PromotionEvidence = {
	reviewed: true,
	runtimeBudgetsProven: true,
	providerFinalityProven: true,
	releaseApproved: true,
	duplicatePaidResultIdentities: 0,
	ownershipPrivacyViolations: 0,
};

describe('Paystack consuming-site integration through the EmDash 1.3 host fixture', () => {
	beforeEach(async () => {
		host = await createPluginRuntimeTestHost();
		runtimeBridge.withEmDashRuntime.mockReset();
	});

	afterEach(async () => {
		await host?.dispose();
	});

	it('keeps public standalone form rendering out of the DashCommerce release', async () => {
		const response = await host.actions.routes.request('form-render', { method: 'GET' });
		expect(response.ok).toBe(false);
		expect(host.http.requests()).toEqual([]);
	});

	it('requires site-owned auth, origin and CSRF before resolving ownership or calling the runtime', async () => {
		let contextCalls = 0;
		const store = createMemoryStore();
		const options = createAdapterOptions(host, store, DEFAULT_ADMISSION_ROLLOUT, {
			resolveSession: async () => ({ transport: 'session', siteId: 'another_site', subject: { kind: 'member', id: 'member-7' } }),
		}, async () => { contextCalls += 1; return fixedContext; });
		const adapter = createPaystackSiteAdapter(options);

		const wrongOrigin = await adapter.submit(siteRequest({ origin: 'https://attacker.example' }));
		expect(wrongOrigin.status).toBe(403);
		const wrongOwner = await adapter.submit(siteRequest());
		expect(wrongOwner.status).toBe(401);
		expect(contextCalls).toBe(0);
		expect(runtimeBridge.withEmDashRuntime).not.toHaveBeenCalled();

		const csrfDenied = createPaystackSiteAdapter(createAdapterOptions(host, store, DEFAULT_ADMISSION_ROLLOUT, {
			verifyCsrf: async () => false,
		}, async () => { contextCalls += 1; return fixedContext; }));
		expect((await csrfDenied.submit(siteRequest())).status).toBe(403);
		expect(contextCalls).toBe(0);
		expect(runtimeBridge.withEmDashRuntime).not.toHaveBeenCalled();
	});

	it('fails closed without durable rate state and refuses an unowned status before raw invocation', async () => {
		const noStore = createPaystackSiteAdapter(createAdapterOptions(host, undefined, DEFAULT_ADMISSION_ROLLOUT));
		expect((await noStore.submit(siteRequest())).status).toBe(503);
		expect(runtimeBridge.withEmDashRuntime).not.toHaveBeenCalled();

		const store = createMemoryStore();
		const adapter = createPaystackSiteAdapter(createAdapterOptions(host, store, DEFAULT_ADMISSION_ROLLOUT, undefined, undefined, async () => null));
		const denied = await adapter.status(siteRequest({ body: {
			schemaVersion: '1.0', intentId: `psk:v1:intents:${'1'.repeat(64)}`,
		} }));
		expect(denied.status).toBe(403);
		expect(runtimeBridge.withEmDashRuntime).not.toHaveBeenCalled();
	});

	it('signs trusted bytes for one configured raw route and maps the host execution/domain refusal safely', async () => {
		const store = createMemoryStore();
		const promoted = promoteAdmission(DEFAULT_ADMISSION_ROLLOUT, 1, evidence);
		expect(promoted.ok).toBe(true);
		if (!promoted.ok) throw new Error('Fixture rollout promotion failed');
		let internalRequest: Request | undefined;
		let invoked: { pluginId: string; method: string; path: string } | undefined;
		bridgeToDeterministicRejectingBackend((call) => { invoked = call; }, (request) => { internalRequest = request; });
		const adapter = createPaystackSiteAdapter(createAdapterOptions(host, store, promoted.state));
		const response = await adapter.submit(siteRequest({
			body: {
				schemaVersion: '1.0', formId: 'fixed_fee', formRevision: '2', requestKey: 'request_key_2',
				fields: { payer_email: 'payer@example.test' },
				// Extra claims must be rejected before they can alter trusted identity or price.
			},
		}));
		expect(response.status).toBe(409);
		expect(await response.json()).toEqual({ code: 'review_required', message: 'This payment needs review before it can continue.' });
		expect(invoked).toEqual({ pluginId: host.manifest.id, method: 'POST', path: '/payments/submit' });
		expect(internalRequest).toBeInstanceOf(Request);
		expect(host.http.requests()).toEqual([]);
		if (!internalRequest) throw new Error('No signed request reached the fixture runtime');
		const rawBody = new Uint8Array(await internalRequest.clone().arrayBuffer());
		const trustedBody = JSON.parse(new TextDecoder().decode(rawBody)) as Record<string, unknown>;
		expect(trustedBody).toMatchObject({
			schemaVersion: '1.0', siteId: 'site_1', subject: { kind: 'member', id: 'member_7' },
			businessReference: 'order_1', merchantProfile: 'merchant_profile_1',
			submission: { formId: 'fixed_fee', formRevision: '2', requestKey: 'request_key_2' },
		});
		expect(trustedBody).not.toHaveProperty('resolvedOrderPrice');
		expect(trustedBody).not.toHaveProperty('providerSecret');
		expect(trustedBody).not.toHaveProperty('requestKey');

		const headers = Object.fromEntries(internalRequest.headers) as Record<string, string>;
		const attestationKey: SiteAttestationKey = {
			provider: 'paystack', siteId: 'site_1', keyId: 'site_key_1', purpose: 'site-payment',
			material: new Uint8Array(32).fill(7), state: 'current',
		};
		const verified = await verifySiteAttestation({
			provider: 'paystack', method: internalRequest.method, route: 'payments/submit', rawBody,
			headers: {
				'x-payment-site-id': headers['x-payment-site-id']!, 'x-payment-key-id': headers['x-payment-key-id']!,
				'x-payment-timestamp': headers['x-payment-timestamp']!, 'x-payment-nonce': headers['x-payment-nonce']!,
				'x-payment-signature': headers['x-payment-signature']!,
			},
			nowMs: 120_000, keys: [attestationKey],
		});
		expect(verified).toMatchObject({ siteId: 'site_1', keyId: 'site_key_1', route: 'payments/submit' });
	});

	it('continues bounded admission stages with identical payload bytes and a fresh attestation nonce', async () => {
		const store = createMemoryStore();
		const promoted = promoteAdmission(DEFAULT_ADMISSION_ROLLOUT, 1, evidence);
		expect(promoted.ok).toBe(true);
		if (!promoted.ok) throw new Error('Fixture rollout promotion failed');
		const calls: Array<{ nonce: string | null; body: Uint8Array }> = [];
		runtimeBridge.withEmDashRuntime.mockImplementation(async (invoke: (runtime: {
			handlePluginApiRoute(pluginId: string, method: string, path: string, request: Request): Promise<unknown>;
		}) => Promise<unknown>) => invoke({
			handlePluginApiRoute: async (pluginId, method, path, request) => {
				expect(pluginId).toBe(host.manifest.id);
				expect(method).toBe('POST');
				expect(path).toBe('/payments/submit');
				calls.push({
					nonce: request.headers.get('x-payment-nonce'),
					body: new Uint8Array(await request.clone().arrayBuffer()),
				});
				return { success: true, data: { ok: true, value: {
					schemaVersion: '1.0', intentId: `psk:v1:intents:${'2'.repeat(64)}`, state: 'initializing',
					deliveryState: 'not_eligible', stage: calls.length === 1 ? 'allocation' : 'provider_work',
				} } };
			},
		}));

		const adapter = createPaystackSiteAdapter(createAdapterOptions(host, store, promoted.state));
		const response = await adapter.submit(siteRequest());
		expect(response.status).toBe(202);
		expect(await response.json()).toMatchObject({
			schemaVersion: '1.0', intentId: `psk:v1:intents:${'2'.repeat(64)}`, stage: 'provider_work', state: 'initializing',
		});
		expect(calls).toHaveLength(2);
		expect(calls[0]?.nonce).toBeTruthy();
		expect(calls[1]?.nonce).toBeTruthy();
		expect(calls[0]?.nonce).not.toBe(calls[1]?.nonce);
		expect(Array.from(calls[0]?.body ?? [])).toEqual(Array.from(calls[1]?.body ?? []));
		expect(host.http.requests()).toEqual([]);
	});
});

const fixedContext: TrustedSubmitContext = {
	merchantProfile: 'merchant_profile_1',
	businessReference: 'order_1',
	publishedFormRevision: '2',
	pricingMode: 'fixed',
	existingIntent: false,
};

function createAdapterOptions(
	runtimeHost: PluginRuntimeTestHost,
	store: PersistentPaymentStore | undefined,
	rollout: AdmissionRolloutState,
	authOverrides: Partial<NonNullable<PaystackSiteAdapterOptions['auth']>> = {},
	resolveSubmitContext: PaystackSiteAdapterOptions['resolveSubmitContext'] = async () => fixedContext,
	resolveOwnedContext: PaystackSiteAdapterOptions['resolveOwnedContext'] = async () => null,
): PaystackSiteAdapterOptions {
	const attestationKey = new Uint8Array(32).fill(7);
	return {
		installedPluginId: runtimeHost.manifest.id,
		siteId: 'site_1',
		keyId: 'site_key_1',
		siteAttestationKey: attestationKey,
		identityHmacKey: new Uint8Array(32).fill(8),
		auth: {
			siteOrigin: 'https://shop.example',
			resolveSession: async () => ({ transport: 'session', siteId: 'site_1', subject: { kind: 'member', id: 'member_7' } }),
			resolveGuestCapability: async () => null,
			verifyCsrf: async () => true,
			...authOverrides,
		},
		...(store ? { store, limiter: createPersistentRateLimiter(store) } : {}),
		rollout,
		resolveSubmitContext,
		resolveOwnedContext,
		now: () => 120_000,
	};
}

function siteRequest(input: { readonly origin?: string; readonly body?: unknown } = {}): Request {
	return new Request('https://shop.example/api/payments/submit', {
		method: 'POST',
		headers: { origin: input.origin ?? 'https://shop.example', 'content-type': 'application/json', 'x-csrf-token': 'csrf-fixture' },
		body: JSON.stringify(input.body ?? {
			schemaVersion: '1.0', formId: 'fixed_fee', formRevision: '2', requestKey: 'request_key_1',
			fields: { payer_email: 'payer@example.test' },
		}),
	});
}

function createMemoryStore(): PersistentPaymentStore {
	const counters = new Map<string, { windowStartMs: number; count: number }>();
	const keyBindings = new Set<string>();
	return {
		durable: true,
		async ensureReady() {},
		async consumeWindow(key, windowStartMs) {
			const current = counters.get(key);
			if (!current || current.windowStartMs < windowStartMs) {
				counters.set(key, { windowStartMs, count: 1 });
				return 1;
			}
			current.count += 1;
			return current.count;
		},
		async bindIdentityKeyFingerprint(fingerprint) {
			if (keyBindings.size > 0 && !keyBindings.has(fingerprint)) return false;
			keyBindings.add(fingerprint);
			return true;
		},
		// This local fixture deliberately selects the admitted test cohort; it is not live rollout evidence.
		async getOrCreateCohort(_identityDigest, _bucket) { return 0; },
	};
}

function bridgeToDeterministicRejectingBackend(
	onInvoke?: (call: { pluginId: string; method: string; path: string }) => void,
	onRequest?: (request: Request) => void,
): void {
	runtimeBridge.withEmDashRuntime.mockImplementation(async (invoke: (runtime: {
		handlePluginApiRoute(pluginId: string, method: string, path: string, request: Request): Promise<unknown>;
	}) => Promise<unknown>) => invoke({
		handlePluginApiRoute: async (pluginId, method, path, request) => {
			if (pluginId !== host.manifest.id || method !== 'POST' || path !== '/payments/submit') {
				throw new Error('Unexpected dynamic plugin route invocation');
			}
			onInvoke?.({ pluginId, method, path });
			onRequest?.(request.clone());
			await request.arrayBuffer();
			return { success: true, data: { ok: false, error: { code: 'review_required' } } };
		},
	}));
}
