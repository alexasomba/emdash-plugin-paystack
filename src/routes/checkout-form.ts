import type { PluginContext, SandboxedRouteContext } from 'emdash/plugin';
import { FORM_MODEL_VERSION, validateFormDefinition } from '../domain/forms.js';
import { hasExactKeys } from '../security/json.js';
import { meterCollection, StageBudget } from '../security/limits.js';
import { isPlainObject, type VersionedCollection } from '../storage/schema.js';
import type { StoredFormRecord } from './forms.js';
import { domainError, domainOk } from './response.js';

/** Install or read a trusted-order definition for Core; no payer-supplied prices. */
export async function checkoutFormRoute(routeCtx: SandboxedRouteContext, ctx: PluginContext): Promise<unknown> {
	const input = routeCtx.input;
	if (!isPlainObject(input) || !hasExactKeys(input, ['action', 'formId']) ||
		(input.action !== 'provision' && input.action !== 'get') ||
		typeof input.formId !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/u.test(input.formId)) {
		return domainError('validation_error');
	}
	const forms = meterCollection(ctx.storage.forms as VersionedCollection<StoredFormRecord>, new StageBudget('admin', Date.now));
	try {
		const existing = await forms.getVersioned(input.formId);
		if (existing) {
			const form = validateFormDefinition(existing.value.definition);
			return form.ok && form.value.id === input.formId && form.value.state === 'published' && form.value.pricing.mode === 'trusted_order'
				? domainOk({ form: form.value }) : domainError('form_unavailable');
		}
		if (input.action === 'get') return domainError('form_unavailable');
		const parsed = validateFormDefinition({
			schemaVersion: '1.0', id: input.formId, revision: '1', state: 'published',
			name: 'DashCommerce checkout', purpose: 'Pay a DashCommerce order.',
			fields: [{ id: 'payer_email', type: 'email', label: 'Email', required: true }],
			pricing: { mode: 'trusted_order', currency: 'NGN', resolution: 'site_server' },
			metadataPolicy: { allowedKeys: [], maxBytes: 1024 },
		});
		if (!parsed.ok) return domainError(parsed.error);
		const form = parsed.value;
		const written = await forms.compareAndSet(form.id, null, {
			modelVersion: FORM_MODEL_VERSION, state: 'published', updatedAt: new Date().toISOString(),
			definition: form, publishedDefinitions: [form], admissionSequence: 0,
		});
		return written.applied ? domainOk({ form }) : domainError('stale_revision');
	} catch {
		return domainError('storage_unavailable');
	}
}
