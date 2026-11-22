import { describe, expect, it } from 'vite-plus/test';
import { createPluginRuntimeTestHost } from '@emdash-cms/plugin-test';

describe('incompatible sandbox bundle', () => {
	it('is rejected by the EmDash 1.3 Worker Loader instead of executing a Node builtin', async () => {
		let host: Awaited<ReturnType<typeof createPluginRuntimeTestHost>> | undefined;
		try {
			host = await createPluginRuntimeTestHost();
			const response = await host.actions.routes.request('probe', { method: 'POST', body: {} });
			expect(response.status).toBe(400);
			expect(await response.json()).toMatchObject({
				success: false,
				error: {
					code: 'ROUTE_ERROR',
					message: expect.stringContaining('No such module "node:fs"'),
				},
			});
		} catch (error) {
			throw new Error(`Expected Worker Loader route rejection, received host setup failure: ${String(error)}`);
		} finally {
			await host?.dispose();
		}
	});
});
