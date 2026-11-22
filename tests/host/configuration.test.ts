import { afterEach, beforeEach, describe, expect, it } from 'vite-plus/test';
import { createPluginRuntimeTestHost, type PluginRuntimeTestHost } from '@emdash-cms/plugin-test';

let host: PluginRuntimeTestHost;

describe('Paystack configuration in the EmDash 1.3 runtime host', () => {
	beforeEach(async () => {
		host = await createPluginRuntimeTestHost();
	});

	afterEach(async () => {
		await host?.dispose();
	});

	it('enforces authentication, plugins:manage permission, and mutation CSRF on configuration routes', async () => {
		const anonymous = await host.actions.routes.request('configuration', {
			method: 'POST', body: { action: 'read' },
		});
		expect(anonymous.status).toBe(401);

		const subscriber = await host.fixtures.user({ email: 'subscriber@example.test', role: 'subscriber' });
		const insufficient = await host.actions.routes.request('configuration', {
			method: 'POST', body: { action: 'read' }, user: subscriber,
		});
		expect(insufficient.status).toBe(403);
		await expect(host.admin.loadPage('/setup', { user: subscriber })).rejects.toThrow(/Plugin admin request failed \(403\)/u);

		const admin = await host.fixtures.user({ email: 'paystack-admin@example.test', role: 'admin' });
		const csrfDenied = await host.actions.routes.request('configuration', {
			method: 'POST', body: { action: 'read' }, user: admin,
		});
		expect(csrfDenied.status).toBe(403);

		const allowed = await host.actions.routes.request('configuration', {
			method: 'POST', headers: { 'x-emdash-request': '1' }, body: { action: 'read' }, user: admin,
		});
		expect(allowed.status).toBe(200);
		expect(await allowed.json()).toMatchObject({
			success: true,
			data: { ok: true, value: { configured: false, paused: true, health: 'unconfigured', revision: null } },
		});
	});

	it('renders the setup page through host Block Kit validation without exposing a secret or calling Paystack', async () => {
		const admin = await host.fixtures.user({ email: 'paystack-admin@example.test', role: 'admin' });
		const response = await host.admin.loadPage('/setup', { user: admin });
		const form = response.blocks.find((block) => block.type === 'form');
		const secretField = form?.type === 'form' ? form.fields.find((field) => field.action_id === 'secretKey') : undefined;

		expect(secretField).toMatchObject({ type: 'secret_input', has_value: false });
		expect(secretField).not.toHaveProperty('value');
		expect(secretField).not.toHaveProperty('initial_value');
		expect(JSON.stringify(response)).toContain('Admission starts paused');
		expect(host.http.requests()).toEqual([]);
	});

	it('fails secret configuration closed when host encryption is unavailable', async () => {
		const admin = await host.fixtures.user({ email: 'paystack-admin@example.test', role: 'admin' });
		const secret = 'sk_test_fixture_notreal_001';
		const page = await host.admin.loadPage('/setup', { user: admin });
		const form = page.blocks.find((block) => block.type === 'form');
		expect(form?.type).toBe('form');
		if (form?.type !== 'form') throw new Error('Setup form was not rendered');
		if (typeof form.block_id !== 'string') throw new Error('Setup form is missing its revision block id');
		const response = await host.admin.submit('/setup', 'save-configuration', {
			environment: 'test', merchantProfile: 'fixture_profile', secretKey: secret,
		}, { user: admin, blockId: form.block_id });

		expect(JSON.stringify(response)).not.toContain(secret);
		expect(JSON.stringify(response)).toContain('Save outcome unknown');
		expect(await host.inspect.settings.raw('paymentConfiguration')).toBeNull();
		expect(host.http.requests()).toEqual([]);
	});

	it('blocks an undeclared outbound host before recording or dispatching an HTTP request', async () => {
		expect(host.manifest.allowedHosts).toEqual(['api.paystack.co']);
		expect(host.manifest.capabilities).toContain('network:request');
		expect(host.manifest.capabilities).not.toContain('network:request:unrestricted');

		const response = await host.actions.routes.request('probe/denied-host', {
			method: 'POST', body: {},
		});
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			success: true,
			data: { ok: true, value: { blocked: true } },
		});
		expect(host.http.requests()).toEqual([]);
	});
});
