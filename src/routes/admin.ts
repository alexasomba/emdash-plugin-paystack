import type { PluginContext, SandboxedRouteContext } from 'emdash/plugin';
import { handleConfiguration, type ConfigurationDependencies, type DomainResult } from '../domain/configuration.js';
import { meterSettings, StageBudget } from '../security/limits.js';
import { domainError, domainOk } from './response.js';

const mapErrorCode: Readonly<Record<string, Parameters<typeof domainError>[0]>> = Object.freeze({
	validation_error: 'validation_error',
	stale_revision: 'stale_revision',
	storage_unavailable: 'storage_unavailable',
	provider_unavailable: 'provider_unavailable',
	review_required: 'review_required',
});

/** Revision-guarded settings and read-only Paystack readiness handler. */
export async function configurationRoute(routeCtx: SandboxedRouteContext, ctx: PluginContext): Promise<unknown> {
	const budget = new StageBudget('admin', () => Date.now());
	const settings = meterSettings(ctx.settings, budget);
	const dependencies: ConfigurationDependencies = {
		settings,
		...(ctx.http ? {
			fetch: (url: string, init?: RequestInit) => budget.run('http', 'http.fetch', () => ctx.http!.fetch(url, init)),
		} : {}),
		now: () => Date.now(),
	};
	const result = await handleConfiguration(routeCtx.input, dependencies);
	return toPluginDomainResult(result);
}

function toPluginDomainResult(result: DomainResult<unknown>): unknown {
	if (result.ok) return domainOk(result.value);
	return domainError(mapErrorCode[result.error.code] ?? 'provider_unavailable');
}
