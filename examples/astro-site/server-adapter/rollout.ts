import type { PaymentSubject } from './auth.js';

export const ROLLOUT_PROMOTION_STEPS = Object.freeze([1, 10, 50, 100] as const);
export type RolloutPercent = 0 | 1 | 10 | 50 | 100;
const guardedState = Symbol('guarded-admission-rollout-state');
const issuedStates = new WeakSet<object>();

export interface AdmissionRolloutState {
	readonly admissionEnabled: boolean;
	readonly paused: boolean;
	readonly percent: RolloutPercent;
	readonly [guardedState]: true;
}

export interface PromotionEvidence {
	readonly reviewed: boolean;
	readonly runtimeBudgetsProven: boolean;
	readonly providerFinalityProven: boolean;
	readonly releaseApproved: boolean;
	readonly duplicatePaidResultIdentities: number;
	readonly ownershipPrivacyViolations: number;
}

export type PromotionResult =
	| { readonly ok: true; readonly state: AdmissionRolloutState }
	| { readonly ok: false; readonly reason: 'invalid_step' | 'gates_incomplete' };

/** New installations always begin paused with no admission cohort. */
export const DEFAULT_ADMISSION_ROLLOUT: AdmissionRolloutState = makeGuardedState(false, true, 0);

/**
 * Binds one trusted business intent to the installation's immutable HMAC key.
 * The returned digest is safe for durable indexes; no subject or order ID is
 * persisted in the rollout table.
 */
export async function assignBusinessIntent(
	identityHmacKey: Uint8Array,
	input: {
		readonly siteId: string;
		readonly subject: PaymentSubject;
		readonly businessReference: string;
	},
	cryptoProvider: Crypto = globalThis.crypto,
): Promise<{ readonly identityDigest: string; readonly bucket: number }> {
	if (!(identityHmacKey instanceof Uint8Array) || identityHmacKey.byteLength !== 32 ||
		!isIdentifier(input.siteId) || !isIdentifier(input.subject.id) || !isIdentifier(input.businessReference)) {
		throw new Error('Stable installation identity inputs are invalid');
	}
	const frame = [
		'emdash-paystack-business-intent-v1',
		part(input.siteId),
		part(input.subject.kind),
		part(input.subject.id),
		part(input.businessReference),
	].join('\n');
	const key = await cryptoProvider.subtle.importKey('raw', toArrayBuffer(identityHmacKey), {
		name: 'HMAC', hash: 'SHA-256',
	}, false, ['sign']);
	const digestBytes = new Uint8Array(await cryptoProvider.subtle.sign(
		'HMAC', key, toArrayBuffer(new TextEncoder().encode(frame)),
	));
	const identityDigest = toHex(digestBytes);
	const prefix = new DataView(toArrayBuffer(digestBytes).slice(0, 4)).getUint32(0, false);
	return Object.freeze({ identityDigest, bucket: prefix % 10_000 });
}

/** Stores only a digest of the key so a rotation cannot silently reset identity fences. */
export async function identityKeyFingerprint(
	identityHmacKey: Uint8Array,
	cryptoProvider: Crypto = globalThis.crypto,
): Promise<string> {
	if (!(identityHmacKey instanceof Uint8Array) || identityHmacKey.byteLength !== 32) {
		throw new Error('Installation identity HMAC key must contain exactly 32 bytes');
	}
	const digest = new Uint8Array(await cryptoProvider.subtle.digest('SHA-256', toArrayBuffer(identityHmacKey)));
	return toHex(digest);
}

/** Manual promotion only; no request, webhook, restart, or cohort can promote itself. */
export function promoteAdmission(
	current: AdmissionRolloutState,
	nextPercent: number,
	evidence: PromotionEvidence,
): PromotionResult {
	if (!isGuardedAdmissionRolloutState(current)) return { ok: false, reason: 'invalid_step' };
	const currentStep = current.percent === 0 ? -1 : ROLLOUT_PROMOTION_STEPS.indexOf(current.percent as 1 | 10 | 50 | 100);
	const nextStep = ROLLOUT_PROMOTION_STEPS.indexOf(nextPercent as 1 | 10 | 50 | 100);
	if (nextStep < 0 || nextStep !== currentStep + 1) return { ok: false, reason: 'invalid_step' };
	if (!hasPromotionEvidence(evidence)) return { ok: false, reason: 'gates_incomplete' };
	return { ok: true, state: makeGuardedState(true, false, nextPercent as RolloutPercent) };
}

/** Reconstructs persisted state only by replaying every manual gated promotion. */
export function restoreAdmissionRolloutState(
	history: readonly { readonly percent: number; readonly evidence: PromotionEvidence }[],
): AdmissionRolloutState | null {
	let state = DEFAULT_ADMISSION_ROLLOUT;
	for (const entry of history) {
		const promoted = promoteAdmission(state, entry.percent, entry.evidence);
		if (!promoted.ok) return null;
		state = promoted.state;
	}
	return state;
}

export function isGuardedAdmissionRolloutState(value: unknown): value is AdmissionRolloutState {
	return typeof value === 'object' && value !== null && issuedStates.has(value) &&
		( value as AdmissionRolloutState )[guardedState] === true;
}

/** Existing intent recovery remains available during a pause and to holdout cohorts. */
export function canSubmitIntent(
	state: AdmissionRolloutState,
	bucket: number,
	existingIntent: boolean,
): boolean {
	if (existingIntent) return true;
	return isGuardedAdmissionRolloutState(state) && state.admissionEnabled && !state.paused && Number.isSafeInteger(bucket) &&
		bucket >= 0 && bucket < 10_000 && bucket < state.percent * 100;
}

function hasPromotionEvidence(value: PromotionEvidence): boolean {
	return value.reviewed && value.runtimeBudgetsProven && value.providerFinalityProven && value.releaseApproved &&
		value.duplicatePaidResultIdentities === 0 && value.ownershipPrivacyViolations === 0;
}

function makeGuardedState(enabled: boolean, paused: boolean, percent: RolloutPercent): AdmissionRolloutState {
	const state = Object.freeze({ admissionEnabled: enabled, paused, percent, [guardedState]: true as const });
	issuedStates.add(state);
	return state;
}

function part(value: string): string {
	return `${new TextEncoder().encode(value).byteLength}:${value}`;
}

function isIdentifier(value: unknown): value is string {
	return typeof value === 'string' && /^[A-Za-z0-9_-]{1,255}$/u.test(value);
}

function toHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
	const copy = new ArrayBuffer(bytes.byteLength);
	new Uint8Array(copy).set(bytes);
	return copy;
}
