import { afterEach, beforeEach, describe, expect, it } from 'vite-plus/test';
import { createPluginRuntimeTestHost, type PluginRuntimeTestHost } from '@emdash-cms/plugin-test';
import paystackPlugin from '../../src/plugin.js';

let host: PluginRuntimeTestHost;

describe('Paystack recovery in the EmDash runtime host', () => {
	beforeEach(async () => {
		host = await createPluginRuntimeTestHost({ site: { url: 'https://cms.example.test' } });
	});

	afterEach(async () => {
		await host?.dispose();
	});

	it('does not register the deferred reporting routes', async () => {
		const admin = await host.fixtures.user({ email: 'recovery-admin@example.test', role: 'admin' });
		const response = await host.actions.routes.request('inspection', {
			method: 'POST', headers: { 'x-emdash-request': '1' }, body: { view: 'payments' }, user: admin,
		});
		expect(paystackPlugin.routes).not.toHaveProperty('inspection');
		expect(response.ok).toBe(false);
	});

	it('restricts recovery to plugin managers and reports an unresolved event without provider work', async () => {
		const admin = await host.fixtures.user({ email: 'recovery-admin@example.test', role: 'admin' });
		const subscriber = await host.fixtures.user({ email: 'recovery-subscriber@example.test', role: 'subscriber' });
		await expect(host.admin.loadPage('/recovery', { user: subscriber })).rejects.toThrow(/Plugin admin request failed \(403\)/u);
		const page = await host.admin.loadPage('/recovery', { user: admin });
		expect(page.blocks).toEqual(expect.arrayContaining([
			expect.objectContaining({ type: 'header', text: 'Recovery' }),
			expect.objectContaining({ type: 'form', block_id: 'recovery-event' }),
		]));

		const result = await host.admin.submit('/recovery', 'reconcile-event', {
			eventId: `psk:v1:inbox:${'a'.repeat(64)}`,
		}, { user: admin, blockId: 'recovery-event' });
		expect(result.blocks).toContainEqual(expect.objectContaining({ type: 'banner', title: 'Recovery needs review' }));
		expect(host.http.requests()).toEqual([]);
	});
});
