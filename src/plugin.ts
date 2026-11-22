import { pluginResponse, type SandboxedPlugin } from 'emdash/plugin';
import { configurationRoute } from './routes/admin.js';
import { checkoutFormRoute } from './routes/checkout-form.js';
import { siteSubmitRoute } from './routes/site.js';
import { siteActionRoute, siteStatusRoute } from './routes/actions.js';
import { paystackWebhookRoute } from './routes/webhook.js';
import { reconciliationRoute } from './routes/reconciliation.js';
import { resultFeedRoute, resultAckRoute } from './routes/results.js';
import { adminPage } from './admin/pages.js';
import {
	cancelPaystackReconciliation,
	runPaystackReconciliationTick,
	schedulePaystackReconciliation,
} from './storage/reconciliation.js';
import { RECONCILIATION_HOOK_TIMEOUT_MS } from './storage/scheduler-health.js';

const ATTESTATION_HEADERS = [
	'x-payment-site-id',
	'x-payment-key-id',
	'x-payment-timestamp',
	'x-payment-nonce',
	'x-payment-signature',
] as const;

const jsonSiteRequest = { body: 'bytes' as const, maxBytes: 65_536, headers: [...ATTESTATION_HEADERS] };
const jsonAdminRequest = { body: 'json' as const, maxBytes: 65_536 };

const plugin: SandboxedPlugin = {
	routes: {
		admin: { permission: 'plugins:manage', handler: adminPage },
		configuration: { methods: ['POST'], request: jsonAdminRequest, permission: 'plugins:manage', handler: configurationRoute },
		forms: { methods: ['POST'], request: jsonAdminRequest, permission: 'plugins:manage', handler: checkoutFormRoute },
		'payments/submit': { methods: ['POST'], request: jsonSiteRequest, handler: siteSubmitRoute },
		'payments/action': { methods: ['POST'], request: jsonSiteRequest, handler: siteActionRoute },
		'payments/status': { methods: ['POST'], request: jsonSiteRequest, handler: siteStatusRoute },
		'provider/webhook': {
			public: true,
			methods: ['POST'],
			// One sentinel byte reaches the handler so it can emit its raw 413 at the 256 KiB ceiling.
			request: { body: 'bytes', maxBytes: 262_145, headers: ['x-paystack-signature'] },
			response: 'raw',
			handler: paystackWebhookRoute,
		},
		reconciliation: { methods: ['POST'], request: jsonAdminRequest, permission: 'plugins:manage', handler: reconciliationRoute },
		'results/feed': { methods: ['POST'], request: jsonSiteRequest, handler: resultFeedRoute },
		'results/ack': { methods: ['POST'], request: jsonSiteRequest, handler: resultAckRoute },
	},
	hooks: {
		'plugin:install': schedulePaystackReconciliation,
		'plugin:activate': schedulePaystackReconciliation,
		'plugin:deactivate': cancelPaystackReconciliation,
		cron: { timeout: RECONCILIATION_HOOK_TIMEOUT_MS, handler: runPaystackReconciliationTick },
	},
};

export default plugin;
