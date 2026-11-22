import { describe, expect, it } from 'vite-plus/test';
import type { PluginContext, SandboxedRouteContext } from 'emdash/plugin';
import { validateFormDefinition, type FormDefinition } from '../../src/domain/forms.js';
import { projectPublishedForm } from '../../src/domain/projection.js';
import { publicFormRoute } from '../../src/routes/public.js';
import type { StoredFormRecord } from '../../src/routes/forms.js';
import { InMemoryFormCollection } from '../support/form-collection.js';
import { approvedExamples } from '../support/spec-fixtures.js';

function published(definitionInput: unknown): FormDefinition {
	const result = validateFormDefinition(definitionInput);
	if (!result.ok) throw new Error('public form fixture is invalid');
	return result.value;
}

function record(definition: FormDefinition): StoredFormRecord {
	return {
		modelVersion: 1,
		state: definition.state,
		updatedAt: '2026-10-18T00:00:00.000Z',
		definition,
		publishedDefinitions: definition.state === 'published' ? [definition] : [],
		admissionSequence: 0,
	};
}

function routeContext(input: unknown): SandboxedRouteContext {
	return { input, request: { method: 'GET', url: 'https://site.example.test/form-render', headers: {} } } as SandboxedRouteContext;
}

describe('public form projection and static form-render route', () => {
	it('returns only allowlisted display fields and fixed amount for a published form', async () => {
		const forms = new InMemoryFormCollection();
		const form = published(approvedExamples.fixedForm);
		forms.seed(form.id, record(form));
		const result = await publicFormRoute(routeContext({ formId: form.id, schemaVersion: '1.0' }), {
			plugin: { id: 'r_opaque_runtime_id' }, storage: { forms },
		} as unknown as PluginContext);

		expect(result).toEqual({ ok: true, value: {
			schemaVersion: '1.0', id: form.id, revision: form.revision,
			purpose: form.purpose, fields: form.fields, pricing: form.pricing,
		} });
		if ('ok' in (result as Record<string, unknown>)) {
			const projection = (result as { value?: Record<string, unknown> }).value;
			expect(projection).not.toHaveProperty('name');
			expect(projection).not.toHaveProperty('state');
			expect(projection).not.toHaveProperty('metadataPolicy');
			expect(projection).not.toHaveProperty('returnDestinationId');
		}
	});

	it('preserves bounded Enter amount limits and trusted-order pricing without a browser-supplied order price', () => {
		const entered = published(approvedExamples.payerEnteredForm);
		const enteredProjection = projectPublishedForm(record(entered), entered.id, '1.0');
		expect(enteredProjection).toMatchObject({ ok: true, value: {
			pricing: { mode: 'payer_entered', minimum: '1000.00', maximum: '100000.00', fractionDigits: 2 },
		} });

		const trustedOrder = published(approvedExamples.orderForm);
		const orderProjection = projectPublishedForm(record(trustedOrder), trustedOrder.id, '1.0');
		expect(orderProjection).toMatchObject({ ok: true, value: {
			pricing: { mode: 'trusted_order', currency: 'NGN', resolution: 'site_server' },
		} });
		expect(orderProjection).not.toHaveProperty('value.pricing.amount');
	});

	it('rejects unsupported versions, unpublished forms, mismatched stored snapshots, and unknown query fields', async () => {
		const form = published(approvedExamples.fixedForm);
		expect(projectPublishedForm(record(form), form.id, '9.0')).toMatchObject({ ok: false, error: { code: 'unsupported_schema' } });
		expect(projectPublishedForm(record({ ...form, state: 'draft' }), form.id, '1.0')).toMatchObject({ ok: false, error: { code: 'form_unavailable' } });
		expect(projectPublishedForm({ ...record(form), internalPaymentAmount: '1.00' }, form.id, '1.0')).toMatchObject({ ok: false, error: { code: 'storage_unavailable' } });

		const forms = new InMemoryFormCollection();
		forms.seed(form.id, record(form));
		const result = await publicFormRoute(routeContext({ formId: form.id, schemaVersion: '1.0', orderPrice: '1.00' }), {
			plugin: { id: 'r_opaque_runtime_id' }, storage: { forms },
		} as unknown as PluginContext);
		expect(result).toMatchObject({ ok: false, error: { code: 'validation_error' } });
	});
});
