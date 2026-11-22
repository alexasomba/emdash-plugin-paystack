export type SitePaymentOperation = 'submit' | 'action' | 'status';
export type PaymentSubjectKind = 'guest' | 'member';

export interface PaymentSubject {
	readonly kind: PaymentSubjectKind;
	readonly id: string;
}

export interface SitePrincipal {
	readonly transport: 'session' | 'guest_capability';
	readonly siteId: string;
	readonly subject: PaymentSubject;
	/** Guest capabilities are short-lived and limited to an explicit operation set. */
	readonly expiresAtMs?: number;
	readonly allowedOperations?: readonly SitePaymentOperation[];
}

export interface SiteAuthDependencies {
	readonly siteOrigin: string;
	readonly resolveSession: (request: Request) => Promise<SitePrincipal | null>;
	readonly resolveGuestCapability: (
		token: string,
		request: Request,
		operation: SitePaymentOperation,
	) => Promise<SitePrincipal | null>;
	/** Delegate CSRF proof to the consuming site's session/capability implementation. */
	readonly verifyCsrf: (
		request: Request,
		principal: SitePrincipal,
		operation: SitePaymentOperation,
	) => Promise<boolean>;
}

export type SiteAuthenticationResult =
	| { readonly ok: true; readonly principal: SitePrincipal }
	| { readonly ok: false; readonly status: 401 | 403 | 405; readonly code: 'unauthorized' | 'forbidden' | 'method_not_allowed' };

/** Resolves only site-owned identities; request JSON never supplies a subject or site ID. */
export async function authenticateSiteRequest(
	request: Request,
	operation: SitePaymentOperation,
	siteId: string,
	dependencies: SiteAuthDependencies | undefined,
	nowMs: number,
): Promise<SiteAuthenticationResult> {
	if (request.method !== 'POST') return { ok: false, status: 405, code: 'method_not_allowed' };
	if (!dependencies || !isIdentifier(siteId) || !Number.isSafeInteger(nowMs) || nowMs < 0) {
		return { ok: false, status: 403, code: 'forbidden' };
	}
	if (!hasExpectedOrigin(request, dependencies.siteOrigin)) {
		return { ok: false, status: 403, code: 'forbidden' };
	}

	let principal: SitePrincipal | null;
	const authorization = request.headers.get('authorization');
	if (authorization !== null) {
		const match = /^Bearer ([A-Za-z0-9._~-]{24,4096})$/u.exec(authorization);
		if (!match) return { ok: false, status: 401, code: 'unauthorized' };
		try {
			principal = await dependencies.resolveGuestCapability(match[1]!, request, operation);
		} catch {
			return { ok: false, status: 401, code: 'unauthorized' };
		}
	} else {
		try {
			principal = await dependencies.resolveSession(request);
		} catch {
			return { ok: false, status: 401, code: 'unauthorized' };
		}
	}

	if (!isPrincipal(principal, siteId, operation, nowMs)) {
		return { ok: false, status: 401, code: 'unauthorized' };
	}
	try {
		if (!(await dependencies.verifyCsrf(request, principal, operation))) {
			return { ok: false, status: 403, code: 'forbidden' };
		}
	} catch {
		return { ok: false, status: 403, code: 'forbidden' };
	}
	return { ok: true, principal };
}

function hasExpectedOrigin(request: Request, configuredOrigin: string): boolean {
	const origin = request.headers.get('origin');
	if (!origin || origin === 'null') return false;
	try {
		const expected = new URL(configuredOrigin);
		const supplied = new URL(origin);
		return supplied.origin === origin && supplied.origin === expected.origin &&
			(expected.protocol === 'https:' || isLocalOrigin(expected));
	} catch {
		return false;
	}
}

function isPrincipal(
	principal: SitePrincipal | null,
	siteId: string,
	operation: SitePaymentOperation,
	nowMs: number,
): principal is SitePrincipal {
	if (!principal || principal.siteId !== siteId || !isSubject(principal.subject)) return false;
	if (principal.transport === 'session') return true;
	if (principal.transport !== 'guest_capability' || !Number.isSafeInteger(principal.expiresAtMs) ||
		principal.expiresAtMs! <= nowMs || !Array.isArray(principal.allowedOperations)) return false;
	return principal.allowedOperations.includes(operation);
}

function isSubject(value: unknown): value is PaymentSubject {
	if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
	const subject = value as Record<string, unknown>;
	return (subject.kind === 'guest' || subject.kind === 'member') && isIdentifier(subject.id);
}

function isIdentifier(value: unknown): value is string {
	return typeof value === 'string' && /^[A-Za-z0-9_-]{1,255}$/u.test(value);
}

function isLocalOrigin(url: URL): boolean {
	return url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1');
}
