export interface PackageIntegrityInput {
	readonly packageVersion: string;
	readonly manifestVersion: string;
	readonly checksum: string;
	readonly expectedChecksum: string;
	readonly imports: readonly string[];
	readonly observedHosts: readonly string[];
	readonly allowedHosts: readonly string[];
}

export interface PackageMetadataInput {
	readonly publisher: string;
	readonly expectedPublisher: string;
	readonly license: string | null;
	readonly authorName: string | null;
	readonly authorUrl: string | null;
	readonly securityUrl: string | null;
	readonly repositoryUrl: string | null;
	readonly claims: readonly string[];
	readonly evidence: readonly string[];
}

export interface ReleaseEvidenceInput {
	readonly uploaded: boolean;
	readonly pluginId: string;
	readonly version: string;
	readonly checksum: string;
	readonly registryDiscovery: boolean;
	readonly cleanInstall: boolean;
	readonly testPayment: boolean;
}

const NODE_BUILTINS = new Set([
	'assert', 'buffer', 'child_process', 'crypto', 'events', 'fs', 'http', 'https', 'module', 'net',
	'os', 'path', 'process', 'stream', 'tls', 'url', 'util', 'worker_threads', 'zlib',
]);

export function validatePackageIntegrity(input: PackageIntegrityInput): readonly string[] {
	const errors: string[] = [];
	if (!input.packageVersion || input.packageVersion !== input.manifestVersion) errors.push('version-mismatch');
	if (!/^[a-f0-9]{64}$/u.test(input.checksum) || input.checksum !== input.expectedChecksum) errors.push('checksum-mismatch');
	if (input.imports.some((specifier) => {
		const path = specifier.replace(/^node:/u, '').split('/')[0]!;
		return NODE_BUILTINS.has(path);
	})) errors.push('node-import');
	const allowed = new Set(input.allowedHosts.map((host) => host.toLowerCase()));
	if (input.observedHosts.some((host) => !allowed.has(host.toLowerCase()))) errors.push('undeclared-host');
	if (input.observedHosts.length > 0 && allowed.size === 0) errors.push('missing-host-allowlist');
	return Object.freeze(errors);
}

export function validatePackageMetadata(input: PackageMetadataInput): readonly string[] {
	const errors: string[] = [];
	if (!input.publisher || input.publisher !== input.expectedPublisher) errors.push('publisher-mismatch');
	if (!input.license || !/^[A-Za-z0-9.+-]{1,64}$/u.test(input.license)) errors.push('license-missing');
	if (!input.authorName || !input.authorUrl || !isHttpsUrl(input.authorUrl)) errors.push('author-missing');
	if (!input.securityUrl || !isHttpsUrl(input.securityUrl)) errors.push('security-contact-missing');
	if (!input.repositoryUrl || !/^https:\/\/github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?$/u.test(input.repositoryUrl)) {
		errors.push('repository-invalid');
	}
	const proven = new Set(input.evidence);
	for (const claim of input.claims) {
		const requiredEvidence = claim === 'supports-live-payments' ? 'live-payment'
			: claim === 'verified-install' ? 'clean-install'
			: claim;
		if (!proven.has(requiredEvidence)) errors.push(`unsupported-claim:${claim}`);
	}
	return Object.freeze(errors);
}

export function evaluateReleaseEvidence(input: ReleaseEvidenceInput): {
	readonly releaseAccepted: boolean;
	readonly missingEvidence: readonly string[];
} {
	const missingEvidence: string[] = [];
	if (!input.uploaded) missingEvidence.push('registry-upload');
	if (!input.registryDiscovery) missingEvidence.push('registry-discovery');
	if (!input.cleanInstall) missingEvidence.push('clean-install');
	if (!input.testPayment) missingEvidence.push('test-payment');
	if (!input.pluginId || !input.version || !/^[a-f0-9]{64}$/u.test(input.checksum)) {
		missingEvidence.push('release-identity');
	}
	return Object.freeze({ releaseAccepted: missingEvidence.length === 0, missingEvidence: Object.freeze(missingEvidence) });
}

function isHttpsUrl(value: string): boolean {
	try { return new URL(value).protocol === 'https:'; } catch { return false; }
}
