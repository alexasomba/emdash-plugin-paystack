import { afterEach, beforeEach, describe, expect, it } from 'vite-plus/test';
import { createPluginRuntimeTestHost, type PluginRuntimeTestHost } from '@emdash-cms/plugin-test';
import { approvedExamples } from '../support/spec-fixtures.js';

let host: PluginRuntimeTestHost;
const formId = 'dashcommerce_checkout';
const provision = { action: 'provision', formId };

describe('DashCommerce checkout definition', () => {
	beforeEach(async () => { host = await createPluginRuntimeTestHost(); });
	afterEach(async () => { await host?.dispose(); });

	it('requires an authenticated plugin manager and the host CSRF header', async () => {
		const admin = await host.fixtures.user({ email: 'checkout-admin@example.test', role: 'admin' });
		const subscriber = await host.fixtures.user({ email: 'checkout-subscriber@example.test', role: 'subscriber' });
		const request = { method: 'POST' as const, body: provision };
		expect((await host.actions.routes.request('forms', request)).status).toBe(401);
		expect((await host.actions.routes.request('forms', { ...request, user: subscriber })).status).toBe(403);
		expect((await host.actions.routes.request('forms', { ...request, user: admin })).status).toBe(403);
		expect(await host.inspect.storage.get('forms', formId)).toBeNull();
	});

	it('provisions a trusted-order definition and leaves its revision intact on replay', async () => {
		const admin = await host.fixtures.user({ email: 'checkout-admin@example.test', role: 'admin' });
		const request = { method: 'POST' as const, headers: { 'x-emdash-request': '1' }, user: admin };
		const missing = await host.actions.routes.request('forms', { ...request, body: { action: 'get', formId } });
		expect(await missing.json()).toMatchObject({ success: true, data: { ok: false, error: { code: 'form_unavailable' } } });
		const first = await host.actions.routes.request('forms', { ...request, body: provision });
		expect(first.status).toBe(200);
		const initial = await first.json();
		expect(initial).toMatchObject({ success: true, data: { ok: true, value: { form: {
			id: formId, revision: '1', state: 'published', pricing: { mode: 'trusted_order', currency: 'NGN', resolution: 'site_server' },
			fields: [{ id: 'payer_email', type: 'email', required: true }],
		} } } });
		for (const action of ['provision', 'get']) {
			const replay = await host.actions.routes.request('forms', { ...request, body: { action, formId } });
			expect(await replay.json()).toEqual(initial);
		}
		expect(await host.inspect.storage.get('forms', formId)).toMatchObject({ state: 'published', admissionSequence: 0 });
		expect(host.http.requests()).toEqual([]);
	});

	it('refuses custom definitions and leaves an existing standalone form unchanged', async () => {
		const admin = await host.fixtures.user({ email: 'checkout-admin@example.test', role: 'admin' });
		const request = { method: 'POST' as const, headers: { 'x-emdash-request': '1' }, user: admin };
		const custom = await host.actions.routes.request('forms', { ...request, body: { ...provision, definition: approvedExamples.fixedForm } });
		expect(await custom.json()).toMatchObject({ success: true, data: { ok: false, error: { code: 'validation_error' } } });
		const definition = { ...approvedExamples.fixedForm, id: formId };
		const existing = { modelVersion: 1, state: 'published', updatedAt: new Date().toISOString(), definition, publishedDefinitions: [definition], admissionSequence: 1 };
		await host.fixtures.plugin.storage('forms', formId, existing);
		const collision = await host.actions.routes.request('forms', { ...request, body: provision });
		expect(await collision.json()).toMatchObject({ success: true, data: { ok: false, error: { code: 'form_unavailable' } } });
		expect(await host.inspect.storage.get('forms', formId)).toEqual(existing);
	});
});
