import { describe, expect, it } from 'vite-plus/test';
import { prepareFinalityProbe } from '../provider/finality-probe.js';

describe('provider finality evidence gate', () => {
	it('defaults to a no-network dry-run listing the three required observations', () => {
		expect(prepareFinalityProbe()).toEqual({
			status: 'dry_run',
			callsMade: 0,
			scenarios: ['fresh_failed_verification', 'abandoned_unknown', 'late_success_same_attempt'],
		});
	});

	it('refuses credentials unless the authorized NGN test target is explicit', () => {
		expect(prepareFinalityProbe({ credentialPresent: true })).toEqual({
			status: 'refused', reason: 'credentials_require_explicit_target', callsMade: 0,
		});
	});

	it('requires an explicitly authorized test account and credentials for that target', () => {
		expect(prepareFinalityProbe({ target: 'authorized-ngn-test', credentialPresent: true })).toEqual({
			status: 'refused', reason: 'authorized_test_account_required', callsMade: 0,
		});
		expect(prepareFinalityProbe({ target: 'authorized-ngn-test', credentialPresent: true, testAccountAuthorized: true }))
			.toMatchObject({ status: 'dry_run', callsMade: 0 });
	});

	it('keeps provider execution disabled even with an explicit authorized target', () => {
		expect(prepareFinalityProbe({
			mode: 'execute', target: 'authorized-ngn-test', credentialPresent: true, testAccountAuthorized: true,
		})).toEqual({ status: 'blocked', reason: 'provider_execution_not_enabled', callsMade: 0 });
	});
});
