import { describe, expect, it } from 'vite-plus/test';
import type { SandboxedRequest } from 'emdash/plugin';
import type { SettingsPort } from '../../src/domain/configuration.js';
import { encodeBase64Url } from '../../src/security/encryption.js';
import { loadConfigurationRuntime } from '../../src/routes/site.js';

const bytes = (n: number) => encodeBase64Url(new Uint8Array(32).fill(n));
const config = {
  schemaVersion: 1, paused: true, activeProfile: null, profiles: {},
  integrationKeys: [
    { siteId: 'shop', keyId: 'payment', purpose: 'site-payment', secretBase64url: bytes(1) },
    { siteId: 'shop', keyId: 'result', purpose: 'result-consumer', consumerId: 'commerce', secretBase64url: bytes(2) },
  ],
  fieldEncryptionKeyRing: { activeKeyId: 'field', keys: [{ keyId: 'field', material: bytes(3) }] },
  identityHmacKeyRing: { activeKeyId: 'identity', keys: [{ keyId: 'identity', material: bytes(4) }] },
};
const settings: SettingsPort = {
  getVersioned: async <T>() => ({ value: JSON.stringify(config) as T, revision: '1' }),
  compareAndSet: async () => ({ applied: false }),
};
const request = (site: string, key: string) => ({
  headers: { 'x-payment-site-id': site, 'x-payment-key-id': key },
}) as unknown as SandboxedRequest;

describe('result consumer configuration', () => {
  it('binds the result key to its configured consumer and purpose', async () => {
    const result = await loadConfigurationRuntime({ pluginId: 'paystack', settings }, request('shop', 'result'), 'result-consumer');
    expect(result?.consumerId).toBe('commerce');
    expect(result?.attestationKey).toMatchObject({ purpose: 'result-consumer', siteId: 'shop', keyId: 'result' });
  });
  it('does not permit a payment key to act as a consumer or a consumer key as a payment key', async () => {
    const deps = { pluginId: 'paystack', settings };
    expect(await loadConfigurationRuntime(deps, request('shop', 'payment'), 'result-consumer')).toBeNull();
    expect(await loadConfigurationRuntime(deps, request('shop', 'result'))).toBeNull();
    expect(await loadConfigurationRuntime(deps, request('other', 'result'), 'result-consumer')).toBeNull();
    expect((await loadConfigurationRuntime(deps, request('shop', 'payment')))?.attestationKey.purpose).toBe('site-payment');
  });
});
