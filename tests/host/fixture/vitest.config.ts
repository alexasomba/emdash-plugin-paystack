import { fileURLToPath } from 'node:url';
import { emdashPluginTest } from '@emdash-cms/plugin-test/config';
import { defineConfig } from 'vite-plus';

export default defineConfig({
  plugins: [emdashPluginTest({ dir: fileURLToPath(new URL('.', import.meta.url)) })],
  test: { include: ['tests/host/boundary.test.ts', 'tests/host/configuration.test.ts', 'tests/host/forms.test.ts', 'tests/host/inspection.test.ts', 'tests/host/site-adapter.test.ts', 'tests/host/payment-action.test.ts', 'tests/host/wallet-routes.test.ts', 'tests/host/webhook.test.ts', 'tests/host/results.test.ts', 'tests/host/dashcommerce-checkout-bridge.test.ts', 'tests/runtime/budget-probe.ts', 'tests/runtime/intent-races.test.ts'] },
});
