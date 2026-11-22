import { describe, expect, it } from 'vite-plus/test';
import { evaluateReleaseEvidence, validatePackageIntegrity, validatePackageMetadata } from '../../scripts/release-check.js';

describe('sandbox package integrity and registry release contracts', () => {
	it('TC-REL-001 rejects mismatched versions, checksums, Node imports, and undeclared host permissions', () => {
		const errors = validatePackageIntegrity({
			packageVersion: '1.0.0', manifestVersion: '0.9.0', checksum: 'a'.repeat(64), expectedChecksum: 'b'.repeat(64),
			imports: ['node:crypto'], observedHosts: ['api.paystack.co', 'unlisted.example.test'], allowedHosts: ['api.paystack.co'],
		});
		expect(errors).toEqual(['version-mismatch', 'checksum-mismatch', 'node-import', 'undeclared-host']);
	});

	it('TC-REL-002 requires publisher identity, license, security contact, and evidence for support claims', () => {
		const errors = validatePackageMetadata({
			publisher: 'did:plc:someone-else', expectedPublisher: 'did:plc:ldzgvxqlbij5imfwfhbsxyou',
			license: null, authorName: 'Alexander Asomba', authorUrl: 'https://bsky.app/profile/alexasomba.bsky.social',
			securityUrl: null, repositoryUrl: 'https://github.com/alexasomba/emdash-plugin-paystack',
			claims: ['supports-live-payments', 'verified-install'], evidence: [],
		});
		expect(errors).toEqual([
			'publisher-mismatch', 'license-missing', 'security-contact-missing',
			'unsupported-claim:supports-live-payments', 'unsupported-claim:verified-install',
		]);
	});

	it('TC-REL-003 distinguishes upload from registry discovery, clean install, and payment evidence', () => {
		const result = evaluateReleaseEvidence({
			uploaded: true, pluginId: 'did:plc:ldzgvxqlbij5imfwfhbsxyou/paystack-payments',
			version: '0.1.1', checksum: 'a'.repeat(64), registryDiscovery: false, cleanInstall: false, testPayment: false,
		});
		expect(result).toEqual({ releaseAccepted: false, missingEvidence: ['registry-discovery', 'clean-install', 'test-payment'] });
		expect(evaluateReleaseEvidence({
			uploaded: true, pluginId: 'did:plc:ldzgvxqlbij5imfwfhbsxyou/paystack-payments',
			version: '0.1.1', checksum: 'a'.repeat(64), registryDiscovery: true, cleanInstall: true, testPayment: true,
		})).toEqual({ releaseAccepted: true, missingEvidence: [] });
	});
});
