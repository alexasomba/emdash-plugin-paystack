import { expect } from 'vite-plus/test';
import type { PluginContext, SandboxedRequest, SandboxedRouteContext } from 'emdash/plugin';
import { handleConfiguration, PAYMENT_CONFIGURATION_SETTING, type SettingsPort, type VersionedSetting } from '../../src/domain/configuration.js';
import { encodeBase64Url, toHex } from '../../src/security/encryption.js';
import { canonicalAttestationFrame, type NonceRecord } from '../../src/security/attestation.js';
import { handleSiteAction } from '../../src/routes/actions.js';
import { handleSiteSubmit, siteSubmitRoute, type SiteSubmitDependencies } from '../../src/routes/site.js';
import type { StoredFormRecord } from '../../src/routes/forms.js';
import type { FormDefinition } from '../../src/domain/forms.js';
import type { AdmissionIntentRecord } from '../../src/storage/admission.js';
import type { RequestKeyRecord } from '../../src/storage/request-keys.js';
import type { ModelRecord, VersionedCollection } from '../../src/storage/schema.js';
import type { PaystackCreateDependencies } from '../../src/provider/paystack.js';
import { schedulerHealthId } from '../../src/storage/scheduler-health.js';
import { approvedExamples } from '../support/spec-fixtures.js';

const NOW = 120_000;
const SITE_ID = 'site_1';
const KEY_ID = 'site_key_1';
const ATTESTATION_KEY = new Uint8Array(32).fill(7);
const FORM = approvedExamples.fixedForm as unknown as FormDefinition;

export async function createFixture(consumers: string[] = []) {
	let storedSetting: unknown = null;
	let settingRevision: string | null = null;
	let revisionNumber = 1;
	let randomByte = 10;
	let settingReadCount = 0;
	const settings: SettingsPort = {
		getVersioned: async <T>(key: string): Promise<VersionedSetting<T> | null> => {
			settingReadCount += 1;
			if (key !== PAYMENT_CONFIGURATION_SETTING || settingRevision === null) return null;
			return { value: storedSetting as T, revision: settingRevision };
		},
		compareAndSet: async (key, expectedRevision, value) => {
			if (key !== PAYMENT_CONFIGURATION_SETTING || expectedRevision !== settingRevision) return { applied: false };
			storedSetting = value;
			settingRevision = `configuration-${revisionNumber++}`;
			return { applied: true, revision: settingRevision };
		},
	};
	const configurationDependencies = {
		settings,
		now: () => NOW,
		randomBytes: (length: number) => new Uint8Array(length).fill(randomByte++),
	};
	const saved = await handleConfiguration({
		action: 'save', environment: 'test', merchantProfile: 'merchant_profile_1',
		credentials: { secretKey: 'sk_test_admission_fixture' }, expectedRevision: null,
		integrationKeys: [{
			siteId: SITE_ID, keyId: KEY_ID, secretBase64url: encodeBase64Url(ATTESTATION_KEY), purpose: 'site-payment',
		}, ...consumers.map((consumerId, index) => ({ siteId: SITE_ID, keyId: `result_key_${index}`,
			secretBase64url: encodeBase64Url(new Uint8Array(32).fill(30 + index)), purpose: 'result-consumer', consumerId }))],
	}, configurationDependencies);
	expect(saved).toMatchObject({ ok: true, value: { revision: 'configuration-1' } });
	const unpaused = await handleConfiguration({ action: 'pause', paused: false, expectedRevision: 'configuration-1' }, configurationDependencies);
	expect(unpaused).toMatchObject({ ok: true, value: { paused: false, revision: 'configuration-2' } });

	const forms = new MemoryCollection<StoredFormRecord>();
	forms.seed(FORM.id, {
		modelVersion: 1,
		state: 'published',
		updatedAt: '2026-10-18T00:00:00.000Z',
		definition: FORM,
		publishedDefinitions: [FORM],
		admissionSequence: 0,
	});
	const nonces = new MemoryCollection<NonceRecord>();
	const requestKeys = new MemoryCollection<RequestKeyRecord>();
	const intents = new MemoryCollection<AdmissionIntentRecord>();
	const budgets = new MemoryCollection<ModelRecord>();
	budgets.seed(schedulerHealthId(), { modelVersion: 1, healthKind: 'paystack-reconciliation-scheduler',
		leaseEpoch: 0, lease: null, lastSuccessfulAt: NOW, oldestDueIntentAt: null, oldestDueInboxAt: null,
		nextQueue: 'intents', providerCooldownUntil: 0, providerCooldownObservedAt: null, expiresAt: Number.MAX_SAFE_INTEGER });
	const dependencies: SiteSubmitDependencies = {
		pluginId: 'emdash-plugin-paystack', settings, nonces, forms, requestKeys, intents, budgets, now: () => NOW,
	};
	return { dependencies, forms, nonces, requestKeys, intents, budgets, settingsReadCount: () => settingReadCount,
		setCredential: async (merchantProfile: string, environment: 'test' | 'live', secretKey: string) =>
			handleConfiguration({ action: 'save', merchantProfile, environment, credentials: { secretKey },
				expectedRevision: settingRevision }, configurationDependencies),
		setConsumers: async (ids: string[]) => handleConfiguration({ action: 'save', environment: 'test',
			merchantProfile: 'merchant_profile_1', expectedRevision: settingRevision, integrationKeys: [
				{ siteId: SITE_ID, keyId: KEY_ID, secretBase64url: encodeBase64Url(ATTESTATION_KEY), purpose: 'site-payment' },
				...ids.map((consumerId, index) => ({ siteId: SITE_ID, keyId: `result_key_${index}`,
					secretBase64url: encodeBase64Url(new Uint8Array(32).fill(30 + index)), purpose: 'result-consumer', consumerId })),
			] }, configurationDependencies) };
}

export function makeTrustedBody(requestKey = 'request_key_1234567890') {
	return {
		schemaVersion: '1.0',
		siteId: SITE_ID,
		subject: { kind: 'member', id: 'member_7' },
		businessReference: 'order_1',
		merchantProfile: 'merchant_profile_1',
		submission: {
			schemaVersion: '1.0',
			formId: FORM.id,
			formRevision: FORM.revision,
			requestKey,
			fields: { payer_email: 'payer@example.test' },
		},
	};
}

export async function invoke(dependencies: SiteSubmitDependencies, body: unknown, nonce: string) {
	const signed = await signedRequest(body, nonce);
	return handleSiteSubmit(signed.raw, signed.request, dependencies);
}

export async function invokeSandboxRoute(
	fixture: Awaited<ReturnType<typeof createFixture>>,
	body: unknown,
	nonce: string,
) {
	const signed = await signedRequest(body, nonce, Date.now());
	const context = {
		plugin: { id: 'emdash-plugin-paystack' },
		settings: fixture.dependencies.settings,
		storage: {
			nonces: fixture.nonces,
			forms: fixture.forms,
			request_keys: fixture.requestKeys,
			intents: fixture.intents,
			budgets: fixture.budgets,
		},
	} as unknown as PluginContext;
	const routeContext = { input: signed.raw, request: signed.request } as SandboxedRouteContext;
	return siteSubmitRoute(routeContext, context);
}

export async function signedRequest(body: unknown, nonce: string, nowMs = NOW, route = 'payments/submit') {
	const raw = new TextEncoder().encode(JSON.stringify(body));
	const timestamp = String(Math.floor(nowMs / 1000));
	const digest = await crypto.subtle.digest('SHA-256', raw);
	const bodyDigest = toHex(new Uint8Array(digest));
	const frame = canonicalAttestationFrame({
		siteId: SITE_ID,
		keyId: KEY_ID,
		timestampSeconds: Number(timestamp),
		nonce,
		method: 'POST',
		route,
		bodyDigest,
	});
	const key = await crypto.subtle.importKey('raw', ATTESTATION_KEY, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const signature = toHex(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(frame))));
	const headers = {
		'x-payment-site-id': SITE_ID,
		'x-payment-key-id': KEY_ID,
		'x-payment-timestamp': timestamp,
		'x-payment-nonce': nonce,
		'x-payment-signature': signature,
	};
	const request = { method: 'POST', headers } as unknown as SandboxedRequest;
	return { raw, headers, request };
}

export async function invokeAction(
	fixture: Awaited<ReturnType<typeof createFixture>>,
	body: unknown,
	nonce: string,
	provider?: Omit<PaystackCreateDependencies, 'pluginId'>,
) {
	const signed = await signedRequest(body, nonce, NOW, 'payments/action');
	return handleSiteAction(signed.raw, signed.request, {
		pluginId: fixture.dependencies.pluginId,
		settings: fixture.dependencies.settings,
		nonces: fixture.nonces,
		intents: fixture.intents,
		...(provider ? { provider } : {}),
		now: () => NOW,
	});
}

class MemoryCollection<T> implements VersionedCollection<T> {
	private readonly records = new Map<string, { revision: string; value: T }>();
	private revision = 1;
	private conflict = false;
	private throwAfterApplyCas: number | null = null;
	readCount = 0;
	writeCount = 0;
	compareAndSetCalls = 0;

	seed(id: string, value: T): void { this.records.set(id, { revision: `fixture-${this.revision++}`, value: structuredClone(value) }); }
	conflictNextCas(): void { this.conflict = true; }
	throwAfterApplyOnCas(call: number): void { this.throwAfterApplyCas = call; }

	async getVersioned(id: string) {
		this.readCount += 1;
		const current = this.records.get(id);
		return current ? { revision: current.revision, value: structuredClone(current.value) } : null;
	}

	async compareAndSet(id: string, expectedRevision: string | null, value: T) {
		this.writeCount += 1;
		this.compareAndSetCalls += 1;
		const current = this.records.get(id);
		if (this.conflict) {
			this.conflict = false;
			if (current) current.revision = `fixture-${this.revision++}`;
			return { applied: false } as const;
		}
		if ((current?.revision ?? null) !== expectedRevision) return { applied: false } as const;
		const revision = `fixture-${this.revision++}`;
		this.records.set(id, { revision, value: structuredClone(value) });
		if (this.throwAfterApplyCas === this.compareAndSetCalls) {
			this.throwAfterApplyCas = null;
			throw new Error('fixture lost the CAS response after applying the write');
		}
		return { applied: true, revision } as const;
	}

	async compareAndDelete(id: string, expectedRevision: string) {
		const current = this.records.get(id);
		if (!current || current.revision !== expectedRevision) return { applied: false };
		this.records.delete(id);
		return { applied: true };
	}

	async query() {
		return { items: [], hasMore: false };
	}

	values(): T[] { return [...this.records.values()].map((entry) => structuredClone(entry.value)); }
}
