import { describe, expect, it } from 'vite-plus/test';
import { renderSetupPage } from '../../src/admin/pages.js';

describe('Paystack setup Block Kit projection', () => {
	it('keeps a configured read distinct from an explicit provider check', () => {
		const page = renderSetupPage({
			environment: 'test', merchantProfile: 'primary_test', configured: true,
			paused: true, health: 'ready', revision: 'cfg-rev-1',
		});
		const serialized = JSON.stringify(page.blocks);

		expect(serialized).toContain('Not checked');
		expect(serialized).toContain('Configured');
		expect(serialized).toContain('Paused');
		expect(serialized).not.toContain('sk_test_');
	});

	it('uses a revision-bound setup form and a write-only secret input', () => {
		const page = renderSetupPage({
			environment: 'test', merchantProfile: 'primary_test', configured: true,
			paused: true, health: 'ready', revision: 'revision:1',
		});
		const form = page.blocks.find((block) => (block as { type?: string }).type === 'form') as {
			block_id: string;
			fields: Array<Record<string, unknown>>;
		};
		const secret = form.fields.find((field) => field.action_id === 'secretKey');

		expect(form.block_id).toBe('setup-save:revision%3A1');
		expect(secret).toMatchObject({ type: 'secret_input', has_value: true });
		expect(secret).not.toHaveProperty('initial_value');
	});

	it('requires an explicit reload after an uncertain save and keeps credentials out of the returned page', () => {
		const page = renderSetupPage({
			environment: 'test', merchantProfile: 'primary_test', configured: true,
			paused: true, health: 'ready', revision: 'cfg-rev-2',
		}, {
			title: 'Save outcome unknown',
			description: 'Review current configuration before saving again.',
			variant: 'alert',
		}, { environment: 'live', merchantProfile: 'primary_live', publicKey: 'pk_live_example' }, { reloadRequired: true });
		const serialized = JSON.stringify(page.blocks);

		expect(page.blocks.some((block) => (block as { type?: string }).type === 'form')).toBe(false);
		expect(serialized).toContain('Reload configuration');
		expect(serialized).toContain('primary_live');
		expect(serialized).not.toContain('sk_live_');
	});
});
