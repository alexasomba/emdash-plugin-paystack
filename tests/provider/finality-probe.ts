export type FinalityProbeMode = 'dry-run' | 'execute';

export interface FinalityProbeInput {
	readonly mode?: FinalityProbeMode;
	readonly target?: string;
	readonly credentialPresent?: boolean;
	readonly testAccountAuthorized?: boolean;
}

export type FinalityProbeDecision =
	| { readonly status: 'dry_run'; readonly callsMade: 0; readonly scenarios: readonly FinalityScenario[] }
	| { readonly status: 'refused'; readonly reason: 'credentials_require_explicit_target' | 'authorized_test_account_required'; readonly callsMade: 0 }
	| { readonly status: 'blocked'; readonly reason: 'provider_execution_not_enabled'; readonly callsMade: 0 };

export type FinalityScenario = 'fresh_failed_verification' | 'abandoned_unknown' | 'late_success_same_attempt';

export const FINALITY_SCENARIOS: readonly FinalityScenario[] = Object.freeze([
	'fresh_failed_verification',
	'abandoned_unknown',
	'late_success_same_attempt',
]);

/** Safety gate for the evidence protocol. It intentionally has no provider client or network capability. */
export function prepareFinalityProbe(input: FinalityProbeInput = {}): FinalityProbeDecision {
	const mode = input.mode ?? 'dry-run';
	const credentialPresent = input.credentialPresent === true;
	if (credentialPresent && input.target !== 'authorized-ngn-test') {
		return Object.freeze({ status: 'refused', reason: 'credentials_require_explicit_target', callsMade: 0 });
	}
	if (input.target === 'authorized-ngn-test' && (input.testAccountAuthorized !== true || !credentialPresent)) {
		return Object.freeze({ status: 'refused', reason: 'authorized_test_account_required', callsMade: 0 });
	}
	if (mode === 'execute') {
		return Object.freeze({ status: 'blocked', reason: 'provider_execution_not_enabled', callsMade: 0 });
	}
	return Object.freeze({ status: 'dry_run', callsMade: 0, scenarios: FINALITY_SCENARIOS });
}
