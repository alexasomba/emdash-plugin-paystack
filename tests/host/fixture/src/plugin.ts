import type { SandboxedPlugin } from 'emdash/plugin';
import paystackPlugin from '../../../../src/plugin.js';
import { probeRoutes } from '../probe.js';
import { recordProbeTick, scheduleProbe } from '../scheduled.js';

const plugin: SandboxedPlugin = {
	...paystackPlugin,
	routes: {
		...paystackPlugin.routes,
		...probeRoutes,
	},
  hooks: {
		...paystackPlugin.hooks,
    'plugin:activate': scheduleProbe,
    cron: { timeout: 25000, handler: recordProbeTick },
  },
};

export default plugin;
