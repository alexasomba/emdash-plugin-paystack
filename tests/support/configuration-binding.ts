import { handleConfiguration, PAYMENT_CONFIGURATION_SETTING, type SettingsPort, type VersionedSetting } from '../../src/domain/configuration.js';
import type { FeatureOperation, PaymentTestDriver } from './driver.js';

/** Binds the Red-gate operation seam to production configuration code and the driver's observable ports. */
export function bindConfigurationBehavior(driver: PaymentTestDriver): void {
	let storedValue: unknown = null;
	let revision: string | null = null;
	const settings: SettingsPort = {
		getVersioned: <T>(key: string): Promise<VersionedSetting<T> | null> => driver.rpc('settings', 'settings.getVersioned', () => {
			if (key !== PAYMENT_CONFIGURATION_SETTING || revision === null) return null;
			return { value: storedValue as T, revision };
		}),
		compareAndSet: (key, expectedRevision, value) => driver.rpc('settings', 'settings.compareAndSet', () => {
			if (key !== PAYMENT_CONFIGURATION_SETTING || expectedRevision !== revision || typeof value !== 'string') {
				return { applied: false as const };
			}
			storedValue = value;
			revision = revision === null ? 'rev-1' : `rev-${Number(revision.slice(4)) + 1}`;
			return { applied: true as const, revision };
		}),
	};
	const dependencies = {
		settings,
		randomBytes: (length: number) => crypto.getRandomValues(new Uint8Array(length)),
		fetch: async (url: string, init?: RequestInit) => {
			const headers = Object.fromEntries(new Headers(init?.headers).entries());
			const result = await driver.network.fetch({ url, method: init?.method ?? 'GET', headers });
			return new Response(result.body, { status: result.status, ...(result.headers ? { headers: result.headers } : {}) });
		},
	};
	const register = (operation: FeatureOperation) => driver.register(operation, async (input) => {
		const result = await handleConfiguration(input, dependencies);
		return result.ok ? result.value : { ok: false, error: { code: result.error.code } };
	});
	register('configuration.read');
	register('configuration.save');
	register('configuration.health');
}
