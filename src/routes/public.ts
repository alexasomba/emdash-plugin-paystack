import type { PluginContext, SandboxedRouteContext } from 'emdash/plugin';
import { projectPublishedForm } from '../domain/projection.js';
import { StageBudget } from '../security/limits.js';
import type { StoredFormRecord } from './forms.js';
import type { VersionedCollection } from '../storage/schema.js';
import { domainError, domainOk } from './response.js';

const PUBLIC_FORM_QUERY_KEYS = ['formId', 'schemaVersion'] as const;

/** Public read-only route. The EmDash host scopes storage to the installed runtime ID. */
export async function publicFormRoute(routeCtx: SandboxedRouteContext, ctx: PluginContext): Promise<unknown> {
	const query = parseQuery(routeCtx.input);
	if (!query) return domainError('validation_error');
	const budget = new StageBudget('public_render', () => Date.now());
	const forms = ctx.storage.forms as VersionedCollection<StoredFormRecord>;
	let stored: { readonly value: StoredFormRecord; readonly revision: string } | null;
	try {
		stored = await budget.run('storage', 'storage.read', () => forms.getVersioned(query.formId));
	} catch {
		return domainError('storage_unavailable');
	}
	if (!stored) return domainError('form_unavailable');
	const result = projectPublishedForm(stored.value, query.formId, query.schemaVersion);
	return result.ok ? domainOk(result.value) : domainError(result.error.code);
}

function parseQuery(input: unknown): { readonly formId: string; readonly schemaVersion: string } | null {
	if (!isRecord(input)) return null;
	const keys = Object.keys(input);
	if (keys.length !== PUBLIC_FORM_QUERY_KEYS.length || PUBLIC_FORM_QUERY_KEYS.some((key) => !Object.hasOwn(input, key))) return null;
	if (typeof input.formId !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/u.test(input.formId) ||
		typeof input.schemaVersion !== 'string' || input.schemaVersion.length > 16) return null;
	return { formId: input.formId, schemaVersion: input.schemaVersion };
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}
