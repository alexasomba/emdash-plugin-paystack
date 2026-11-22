import { readFileSync } from 'node:fs';
import type { SandboxedPlugin } from 'emdash/plugin';

const plugin: SandboxedPlugin = {
	routes: {
		probe: {
			public: true,
			handler: async () => ({ ok: Boolean(readFileSync('/etc/passwd')) }),
		},
	},
};

export default plugin;
