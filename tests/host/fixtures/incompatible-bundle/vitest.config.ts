import { fileURLToPath } from 'node:url';
import { emdashPluginTest } from '@emdash-cms/plugin-test/config';
import { defineConfig } from 'vite-plus';

export default defineConfig({
	plugins: [emdashPluginTest({ dir: fileURLToPath(new URL('.', import.meta.url)) })],
	test: { include: ['tests/host/fixtures/incompatible-bundle/incompatible.test.ts'] },
});
