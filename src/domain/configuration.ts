import { decodeBase64Url, encodeBase64Url } from '../security/encryption.js';
import { parseStrictJson } from '../security/json.js';
import { isPlainObject, MAX_AGGREGATE_BYTES, StorageInvariantError } from '../storage/schema.js';

export const PAYMENT_CONFIGURATION_SETTING = 'paymentConfiguration';
export const MAX_CONFIGURATION_BYTES = MAX_AGGREGATE_BYTES;
export const CONFIGURATION_SCHEMA_VERSION = 1 as const;
const KEY_ID = /^[A-Za-z0-9_-]{1,64}$/u;
const IDENTIFIER = /^[A-Za-z0-9_-]{1,120}$/u;
const MAX_PROFILES = 32;
/** Keep provider signature verification bounded until a drained version can be retired safely. */
export const MAX_CREDENTIAL_VERSIONS_PER_PROFILE = 16;

export type PaymentEnvironment = 'test' | 'live';
export type IntegrationPurpose = 'site-payment' | 'result-consumer';

export interface CredentialVersion {
	readonly version: number;
	readonly environment: PaymentEnvironment;
	readonly secretKey: string;
	readonly publicKey?: string;
}

export interface MerchantProfile {
	readonly profileId: string;
	readonly activeCredentialVersion: number;
	readonly credentialVersions: readonly CredentialVersion[];
}

export interface IntegrationKey {
	readonly siteId: string;
	readonly keyId: string;
	readonly secretBase64url: string;
	readonly purpose: IntegrationPurpose;
	readonly consumerId?: string;
	readonly privacyErase?: boolean;
}

export interface StoredKey {
	readonly keyId: string;
	readonly material: string;
}

export interface StoredKeyRing {
	readonly activeKeyId: string;
	readonly keys: readonly StoredKey[];
}

/** The only authoritative configuration value; persisted as a JSON string in the host-encrypted setting. */
export interface StoredPaymentConfiguration {
	readonly schemaVersion: typeof CONFIGURATION_SCHEMA_VERSION;
	readonly paused: boolean;
	readonly activeProfile: string | null;
	readonly profiles: Readonly<Record<string, MerchantProfile>>;
	readonly integrationKeys: readonly IntegrationKey[];
	readonly fieldEncryptionKeyRing: StoredKeyRing;
	readonly identityHmacKeyRing: StoredKeyRing;
}

export interface ConfigurationState {
	readonly environment?: PaymentEnvironment;
	readonly merchantProfile?: string;
	readonly paused: boolean;
	readonly configured: boolean;
	readonly health: 'unconfigured' | 'ready' | 'error' | 'incompatible';
	readonly revision: string | null;
}

export type DomainResult<T> =
	| { readonly ok: true; readonly value: T }
	| { readonly ok: false; readonly error: { readonly code: string } };

export interface VersionedSetting<T> {
	readonly value: T;
	readonly revision: string;
}

export interface SettingsPort {
	getVersioned<T>(key: string): Promise<VersionedSetting<T> | null>;
	compareAndSet(key: string, expectedRevision: string | null, value: unknown): Promise<{ applied: true; revision: string } | { applied: false }>;
}

export interface ConfigurationDependencies {
	readonly settings: SettingsPort;
	readonly fetch?: (url: string, init?: RequestInit) => Promise<Response>;
	readonly now?: () => number;
	readonly randomBytes?: (length: number) => Uint8Array;
}

export async function handleConfiguration(input: unknown, dependencies: ConfigurationDependencies): Promise<DomainResult<unknown>> {
	try {
		if (!isPlainObject(input) || typeof input.action !== 'string') return failure('validation_error');
		const action = input.action;
		if (action === 'save' || action === 'pause') {
			const allowNull = action === 'save';
			if (!isRevision(input.expectedRevision, allowNull)) return failure('validation_error');
			const current = await loadConfiguration(dependencies);
			if (current.kind === 'error') return failure('storage_unavailable');
			if (current.revision !== input.expectedRevision) return failure('stale_revision');
			if (!isExactActionShape(input)) return failure('validation_error');
			if (action === 'save') return saveConfiguration(input, dependencies, current);
			return pauseConfiguration(input, dependencies, current);
		}
		if (!isExactActionShape(input)) return failure('validation_error');
		if (action === 'read') return readConfiguration(dependencies);
		if (action === 'health') return checkHealth(dependencies);
		return failure('review_required');
	} catch {
		return failure('storage_unavailable');
	}
}

async function readConfiguration(dependencies: ConfigurationDependencies): Promise<DomainResult<ConfigurationState>> {
	const current = await loadConfiguration(dependencies);
	if (current.kind === 'error') return failure('storage_unavailable');
	return success(projectState(current.value, current.revision, 'ready'));
}

async function checkHealth(dependencies: ConfigurationDependencies): Promise<DomainResult<ConfigurationState>> {
	const current = await loadConfiguration(dependencies);
	if (current.kind === 'error') return failure('storage_unavailable');
	const state = projectState(current.value, current.revision, 'ready');
	if (!state.configured) return success({ ...state, health: 'unconfigured' });
	if (!current.value) return success({ ...state, health: 'unconfigured' });
	const profile = getActiveCredential(current.value);
	if (!profile || !dependencies.fetch) return success({ ...state, health: 'error' });
	try {
		const response = await dependencies.fetch('https://api.paystack.co/integration/payment_session_timeout', {
			method: 'GET',
			headers: { accept: 'application/json', authorization: `Bearer ${profile.secretKey}` },
			redirect: 'error',
		});
		if (!response.ok) return success({ ...state, health: 'error' });
		const bytes = new Uint8Array(await response.arrayBuffer());
		const body = parseStrictJson(bytes, MAX_CONFIGURATION_BYTES);
		if (!isPlainObject(body) || body.status !== true || !isPlainObject(body.data)) {
			return success({ ...state, health: 'incompatible' });
		}
		const timeout = body.data.payment_session_timeout;
		if (typeof timeout !== 'number' || !Number.isSafeInteger(timeout) || timeout <= 0) {
			return success({ ...state, health: 'incompatible' });
		}
		// This read-only endpoint establishes only endpoint/credential compatibility, not merchant identity or payment finality.
		return success({ ...state, health: 'ready' });
	} catch {
		return success({ ...state, health: 'error' });
	}
}

async function saveConfiguration(
	input: Record<string, unknown>,
	dependencies: ConfigurationDependencies,
	current: Extract<LoadedConfiguration, { kind: 'loaded' }>,
): Promise<DomainResult<ConfigurationState>> {
	if (!isEnvironment(input.environment) || !isIdentifier(input.merchantProfile) || !isRevision(input.expectedRevision, true)) {
		return failure('validation_error');
	}
	if (Object.hasOwn(input, 'credentials') && !isCredentialInput(input.credentials)) return failure('validation_error');
	if (Object.hasOwn(input, 'integrationKeys') && !isIntegrationKeyList(input.integrationKeys)) return failure('validation_error');

	const existingProfile = current.value?.profiles[input.merchantProfile];
	if (!existingProfile && Object.keys(current.value?.profiles ?? {}).length >= MAX_PROFILES) return failure('validation_error');
	if (existingProfile && existingProfile.credentialVersions.length >= MAX_CREDENTIAL_VERSIONS_PER_PROFILE) {
		return failure('review_required');
	}
	const existingCredential = existingProfile ? getCredentialVersion(existingProfile, existingProfile.activeCredentialVersion) : undefined;
	const reusableCredential = existingCredential?.environment === input.environment ? existingCredential : undefined;
	const credentialInput = isPlainObject(input.credentials) ? input.credentials : Object.create(null) as Record<string, unknown>;
	const secretKey = Object.hasOwn(credentialInput, 'secretKey') ? credentialInput.secretKey : reusableCredential?.secretKey;
	const publicKey = Object.hasOwn(credentialInput, 'publicKey') ? credentialInput.publicKey : reusableCredential?.publicKey;
	if (typeof secretKey !== 'string' || !hasEnvironmentPrefix(secretKey, input.environment)) return failure('validation_error');
	if (publicKey !== undefined && (typeof publicKey !== 'string' || !hasPublicKeyPrefix(publicKey, input.environment))) {
		return failure('validation_error');
	}

	const next = current.value ?? await createEmptyConfiguration(dependencies);
	const profileBefore = next.profiles[input.merchantProfile];
	const nextVersion = profileBefore ? maxCredentialVersion(profileBefore) + 1 : 1;
	const credential: CredentialVersion = Object.freeze({
		version: nextVersion,
		environment: input.environment,
		secretKey,
		...(typeof publicKey === 'string' ? { publicKey } : {}),
	});
	const profile: MerchantProfile = Object.freeze({
		profileId: input.merchantProfile,
		activeCredentialVersion: nextVersion,
		credentialVersions: Object.freeze([...(profileBefore?.credentialVersions ?? []), credential]),
	});
	const profiles = Object.freeze({ ...next.profiles, [input.merchantProfile]: profile });
	const integrationKeys = Object.hasOwn(input, 'integrationKeys')
		? input.integrationKeys as IntegrationKey[]
		: next.integrationKeys;
	const updated: StoredPaymentConfiguration = Object.freeze({
		...next,
		paused: next.paused,
		activeProfile: input.merchantProfile,
		profiles,
		integrationKeys: Object.freeze([...integrationKeys]),
	});
	return persistConfiguration(updated, input.expectedRevision, current.revision, dependencies);
}

async function pauseConfiguration(
	input: Record<string, unknown>,
	dependencies: ConfigurationDependencies,
	current: Extract<LoadedConfiguration, { kind: 'loaded' }>,
): Promise<DomainResult<ConfigurationState>> {
	if (typeof input.paused !== 'boolean' || !isRevision(input.expectedRevision, false)) return failure('validation_error');
	if (!current.value || current.revision !== input.expectedRevision) return failure('stale_revision');
	const updated: StoredPaymentConfiguration = Object.freeze({ ...current.value, paused: input.paused });
	return persistConfiguration(updated, input.expectedRevision, current.revision, dependencies);
}

async function persistConfiguration(
	configuration: StoredPaymentConfiguration,
	expectedRevision: string | null,
	currentRevision: string | null,
	dependencies: ConfigurationDependencies,
): Promise<DomainResult<ConfigurationState>> {
	if (currentRevision !== expectedRevision) return failure('stale_revision');
	let serialized: string;
	try {
		serialized = JSON.stringify(configuration);
	} catch {
		return failure('storage_unavailable');
	}
	if (new TextEncoder().encode(serialized).byteLength > MAX_CONFIGURATION_BYTES) return failure('validation_error');
	try {
		const write = await dependencies.settings.compareAndSet(PAYMENT_CONFIGURATION_SETTING, expectedRevision, serialized);
		if (!write.applied) return failure('stale_revision');
		return success(projectState(configuration, write.revision, 'ready'));
	} catch {
		// CAS errors can follow a committed write. Never retry or claim a revision that was not returned.
		return failure('storage_unavailable');
	}
}

type LoadedConfiguration =
	| { readonly kind: 'loaded'; readonly value: StoredPaymentConfiguration | null; readonly revision: string | null }
	| { readonly kind: 'error' };

async function loadConfiguration(dependencies: ConfigurationDependencies): Promise<LoadedConfiguration> {
	let versioned: VersionedSetting<unknown> | null;
	try {
		versioned = await dependencies.settings.getVersioned<unknown>(PAYMENT_CONFIGURATION_SETTING);
	} catch {
		return { kind: 'error' };
	}
	if (!versioned) return { kind: 'loaded', value: null, revision: null };
	if (typeof versioned.value !== 'string' || !isOpaqueRevision(versioned.revision)) return { kind: 'error' };
	try {
		const value = parseStrictJson(new TextEncoder().encode(versioned.value), MAX_CONFIGURATION_BYTES);
		const configuration = validateStoredConfiguration(value);
		return configuration
			? { kind: 'loaded', value: configuration, revision: versioned.revision }
			: { kind: 'error' };
	} catch {
		return { kind: 'error' };
	}
}

async function createEmptyConfiguration(dependencies: ConfigurationDependencies): Promise<StoredPaymentConfiguration> {
	const randomBytes = dependencies.randomBytes ?? ((length: number) => crypto.getRandomValues(new Uint8Array(length)));
	const fieldKey = randomBytes(32);
	const identityKey = randomBytes(32);
	if (!(fieldKey instanceof Uint8Array) || fieldKey.byteLength !== 32 || !(identityKey instanceof Uint8Array) || identityKey.byteLength !== 32) {
		throw new StorageInvariantError('INVALID_KEY_MATERIAL');
	}
	if (bytesEqual(fieldKey, identityKey)) throw new StorageInvariantError('KEY_PURPOSE_REUSE');
	return Object.freeze({
		schemaVersion: CONFIGURATION_SCHEMA_VERSION,
		paused: true,
		activeProfile: null,
		profiles: Object.freeze({}),
		integrationKeys: Object.freeze([]),
		fieldEncryptionKeyRing: Object.freeze({
			activeKeyId: 'field-v1',
			keys: Object.freeze([Object.freeze({ keyId: 'field-v1', material: encodeBase64Url(fieldKey) })]),
		}),
		identityHmacKeyRing: Object.freeze({
			activeKeyId: 'identity-v1',
			keys: Object.freeze([Object.freeze({ keyId: 'identity-v1', material: encodeBase64Url(identityKey) })]),
		}),
	});
}

function validateStoredConfiguration(value: unknown): StoredPaymentConfiguration | null {
	if (!isPlainObject(value) || !hasExactKeys(value, [
		'schemaVersion', 'paused', 'activeProfile', 'profiles', 'integrationKeys', 'fieldEncryptionKeyRing', 'identityHmacKeyRing',
	])) return null;
	if (value.schemaVersion !== CONFIGURATION_SCHEMA_VERSION || typeof value.paused !== 'boolean') return null;
	if (value.activeProfile !== null && !isIdentifier(value.activeProfile)) return null;
	if (!isPlainObject(value.profiles) || Object.keys(value.profiles).length > MAX_PROFILES || !isIntegrationKeyList(value.integrationKeys)) return null;
	const profiles: Record<string, MerchantProfile> = Object.create(null) as Record<string, MerchantProfile>;
	for (const [id, candidate] of Object.entries(value.profiles)) {
		if (!isIdentifier(id) || !isPlainObject(candidate) || !hasExactKeys(candidate, ['profileId', 'activeCredentialVersion', 'credentialVersions'])) return null;
		if (candidate.profileId !== id || !Number.isSafeInteger(candidate.activeCredentialVersion) || !Array.isArray(candidate.credentialVersions)) return null;
		const versions: CredentialVersion[] = [];
		let priorVersion = 0;
		for (const rawVersion of candidate.credentialVersions) {
			if (!isPlainObject(rawVersion) || !hasOnlyKeys(rawVersion, ['version', 'environment', 'secretKey', 'publicKey'])) return null;
			if (!Number.isSafeInteger(rawVersion.version) || (rawVersion.version as number) <= priorVersion || !isEnvironment(rawVersion.environment)) return null;
			if (typeof rawVersion.secretKey !== 'string' || !hasEnvironmentPrefix(rawVersion.secretKey, rawVersion.environment)) return null;
			if (rawVersion.publicKey !== undefined && (typeof rawVersion.publicKey !== 'string' || !hasPublicKeyPrefix(rawVersion.publicKey, rawVersion.environment))) return null;
			const version = Object.freeze({
				version: rawVersion.version as number,
				environment: rawVersion.environment,
				secretKey: rawVersion.secretKey,
				...(typeof rawVersion.publicKey === 'string' ? { publicKey: rawVersion.publicKey } : {}),
			});
			versions.push(version);
			priorVersion = version.version;
		}
		if (versions.length === 0 || priorVersion !== candidate.activeCredentialVersion) return null;
		profiles[id] = Object.freeze({ profileId: id, activeCredentialVersion: priorVersion, credentialVersions: Object.freeze(versions) });
	}
	if (value.activeProfile !== null && !Object.hasOwn(profiles, value.activeProfile)) return null;
	const fieldRing = validateKeyRing(value.fieldEncryptionKeyRing);
	const identityRing = validateKeyRing(value.identityHmacKeyRing);
	if (!fieldRing || !identityRing) return null;
	for (const fieldKey of fieldRing.keys) {
		for (const identityKey of identityRing.keys) {
			if (fieldKey.material === identityKey.material) return null;
		}
	}
	return Object.freeze({
		schemaVersion: CONFIGURATION_SCHEMA_VERSION,
		paused: value.paused,
		activeProfile: value.activeProfile as string | null,
		profiles: Object.freeze(profiles),
		integrationKeys: Object.freeze(value.integrationKeys as IntegrationKey[]),
		fieldEncryptionKeyRing: fieldRing,
		identityHmacKeyRing: identityRing,
	});
}

/** Parse a persisted configuration through the same strict schema used by admin settings. */
export function parsePaymentConfigurationSetting(value: unknown): StoredPaymentConfiguration | null {
	if (typeof value !== 'string') return null;
	try {
		return parseStoredPaymentConfiguration(parseStrictJson(new TextEncoder().encode(value), MAX_CONFIGURATION_BYTES));
	} catch {
		return null;
	}
}

export async function readPaymentConfiguration(settings: SettingsPort): Promise<StoredPaymentConfiguration | null> {
	try {
		const stored = await settings.getVersioned<unknown>(PAYMENT_CONFIGURATION_SETTING);
		return parsePaymentConfigurationSetting(stored?.value);
	} catch {
		return null;
	}
}

export function parseStoredPaymentConfiguration(value: unknown): StoredPaymentConfiguration | null {
	return validateStoredConfiguration(value);
}

function validateKeyRing(value: unknown): StoredKeyRing | null {
	if (!isPlainObject(value) || !hasExactKeys(value, ['activeKeyId', 'keys']) || !Array.isArray(value.keys) || value.keys.length < 1 || value.keys.length > 16) return null;
	if (typeof value.activeKeyId !== 'string' || !KEY_ID.test(value.activeKeyId)) return null;
	const keys: StoredKey[] = [];
	const seen = new Set<string>();
	for (const raw of value.keys) {
		if (!isPlainObject(raw) || !hasExactKeys(raw, ['keyId', 'material']) || typeof raw.keyId !== 'string' || !KEY_ID.test(raw.keyId) || seen.has(raw.keyId)) return null;
		if (typeof raw.material !== 'string') return null;
		try {
			if (decodeBase64Url(raw.material).byteLength !== 32) return null;
		} catch { return null; }
		seen.add(raw.keyId);
		keys.push(Object.freeze({ keyId: raw.keyId, material: raw.material }));
	}
	if (!seen.has(value.activeKeyId)) return null;
	return Object.freeze({ activeKeyId: value.activeKeyId, keys: Object.freeze(keys) });
}

function isIntegrationKeyList(value: unknown): value is IntegrationKey[] {
	if (!Array.isArray(value) || value.length > 4) return false;
	const scopes = new Set<string>();
	const scopeCounts = new Map<string, number>();
	for (const entry of value) {
		if (!isPlainObject(entry) || !hasOnlyKeys(entry, ['siteId', 'keyId', 'secretBase64url', 'purpose', 'consumerId', 'privacyErase'])) return false;
		if (!isIdentifier(entry.siteId) || !isIdentifier(entry.keyId) || typeof entry.secretBase64url !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(entry.secretBase64url)) return false;
		try { if (decodeBase64Url(entry.secretBase64url).byteLength !== 32) return false; } catch { return false; }
		if (entry.purpose !== 'site-payment' && entry.purpose !== 'result-consumer') return false;
		if (entry.consumerId !== undefined && !isIdentifier(entry.consumerId)) return false;
		if (entry.purpose === 'result-consumer' && entry.consumerId === undefined) return false;
		if (entry.purpose === 'site-payment' && entry.consumerId !== undefined) return false;
		if (entry.privacyErase !== undefined && typeof entry.privacyErase !== 'boolean') return false;
		if (entry.privacyErase === true && entry.purpose !== 'site-payment') return false;
		const scope = `${entry.siteId}\0${entry.purpose}\0${entry.keyId}`;
		if (scopes.has(scope)) return false;
		scopes.add(scope);
		const ring = `${entry.siteId}\0${entry.purpose}`;
		const count = (scopeCounts.get(ring) ?? 0) + 1;
		if (count > 2) return false;
		scopeCounts.set(ring, count);
	}
	return true;
}

function projectState(configuration: StoredPaymentConfiguration | null, revision: string | null, health: ConfigurationState['health']): ConfigurationState {
	if (!configuration || !configuration.activeProfile) {
		return Object.freeze({ paused: configuration?.paused ?? true, configured: false, health: 'unconfigured', revision });
	}
	const profile = configuration.profiles[configuration.activeProfile];
	const credential = profile ? getCredentialVersion(profile, profile.activeCredentialVersion) : undefined;
	if (!profile || !credential) return Object.freeze({ paused: true, configured: false, health: 'incompatible', revision });
	return Object.freeze({
		environment: credential.environment,
		merchantProfile: configuration.activeProfile,
		paused: configuration.paused,
		configured: true,
		health,
		revision,
	});
}

function getActiveCredential(configuration: StoredPaymentConfiguration): CredentialVersion | undefined {
	if (!configuration.activeProfile) return undefined;
	const profile = configuration.profiles[configuration.activeProfile];
	return profile ? getCredentialVersion(profile, profile.activeCredentialVersion) : undefined;
}

function getCredentialVersion(profile: MerchantProfile, version: number): CredentialVersion | undefined {
	return profile.credentialVersions.find((candidate) => candidate.version === version);
}

function maxCredentialVersion(profile: MerchantProfile): number {
	return profile.credentialVersions.reduce((maximum, candidate) => Math.max(maximum, candidate.version), 0);
}

function isExactActionShape(value: Record<string, unknown>): boolean {
	const allowed = new Set(['action', 'environment', 'merchantProfile', 'paused', 'credentials', 'integrationKeys', 'expectedRevision']);
	return Object.keys(value).every((key) => allowed.has(key)) && typeof value.action === 'string';
}

function isCredentialInput(value: unknown): boolean {
	return isPlainObject(value) && hasOnlyKeys(value, ['secretKey', 'publicKey']) &&
		(value.secretKey === undefined || isCredentialString(value.secretKey)) &&
		(value.publicKey === undefined || isCredentialString(value.publicKey));
}

function isCredentialString(value: unknown): value is string {
	return typeof value === 'string' && value.length > 0 && new TextEncoder().encode(value).byteLength <= 4096 && !/[\u0000-\u001f\u007f]/u.test(value);
}

function hasEnvironmentPrefix(value: string, environment: PaymentEnvironment): boolean {
	const prefix = environment === 'test' ? 'sk_test_' : 'sk_live_';
	return isCredentialString(value) && value.startsWith(prefix) && /^[A-Za-z0-9_-]+$/u.test(value.slice(prefix.length));
}

function hasPublicKeyPrefix(value: string, environment: PaymentEnvironment): boolean {
	const prefix = environment === 'test' ? 'pk_test_' : 'pk_live_';
	return isCredentialString(value) && value.startsWith(prefix) && /^[A-Za-z0-9_-]+$/u.test(value.slice(prefix.length));
}

function isEnvironment(value: unknown): value is PaymentEnvironment {
	return value === 'test' || value === 'live';
}

function isIdentifier(value: unknown): value is string {
	return typeof value === 'string' && IDENTIFIER.test(value);
}

function isRevision(value: unknown, allowNull: boolean): value is string | null {
	return (allowNull && value === null) || isOpaqueRevision(value);
}

function isOpaqueRevision(value: unknown): value is string {
	return typeof value === 'string' && value.length > 0 && value.length <= 256 && !/[\u0000-\u001f\u007f]/u.test(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
	return Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function hasOnlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
	return Object.keys(value).every((key) => keys.includes(key));
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
	if (left.byteLength !== right.byteLength) return false;
	let difference = 0;
	for (let index = 0; index < left.byteLength; index += 1) difference |= left[index]! ^ right[index]!;
	return difference === 0;
}

function success<T>(value: T): DomainResult<T> {
	return Object.freeze({ ok: true, value });
}

function failure(code: string): DomainResult<never> {
	return Object.freeze({ ok: false, error: Object.freeze({ code }) });
}
