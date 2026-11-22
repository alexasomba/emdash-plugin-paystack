import { describe, expect, it } from 'vite-plus/test';
import { createDataEncryptionKey, createIndexHmacKey, decryptValue, encryptValue } from '../../src/security/encryption.js';
import { deriveIntentId } from '../../src/domain/intent.js';
import { assertBoundedRecord, assertSupportedRecord, type ModelRecord, type VersionedCollection } from '../../src/storage/schema.js';
import { VersionedRepository } from '../../src/storage/aggregates.js';
import { parseStrictJson } from '../../src/security/json.js';
import { handleConfiguration, type SettingsPort } from '../../src/domain/configuration.js';

const aad = { pluginId: 'paystack', collection: 'intents', recordId: 'intent_1', schemaVersion: 1, purpose: 'payer_email' as const };
describe('foundation security and persistence contracts', () => {
  it('TC-FND-001 fails closed for missing, wrong, rotated, or AAD-substituted encryption keys', async () => {
    const key = createDataEncryptionKey('key-v1', new Uint8Array(32).fill(1));
    const wrong = createDataEncryptionKey('key-v1', new Uint8Array(32).fill(2));
    const rotated = createDataEncryptionKey('key-v2', new Uint8Array(32).fill(3));
    const encrypted = await encryptValue({ email: 'private-payer@example.test' }, key, aad);
    await expect(decryptValue(encrypted, new Map(), aad)).rejects.toThrow('ENCRYPTION_KEY_UNAVAILABLE');
    await expect(decryptValue(encrypted, new Map([[wrong.keyId, wrong]]), aad)).rejects.toThrow('DECRYPTION_FAILED');
    await expect(decryptValue(encrypted, new Map([[rotated.keyId, rotated]]), aad)).rejects.toThrow('ENCRYPTION_KEY_UNAVAILABLE');
    await expect(decryptValue(encrypted, new Map([[key.keyId, key]]), { ...aad, recordId: 'another_record' })).rejects.toThrow('DECRYPTION_FAILED');
    await expect(decryptValue(encrypted, new Map([[key.keyId, key]]), { ...aad, purpose: 'subject' })).rejects.toThrow('DECRYPTION_FAILED');
    expect(await decryptValue(encrypted, new Map([[key.keyId, key], [rotated.keyId, rotated]]), aad)).toEqual({ email: 'private-payer@example.test' });
    let providerCalls = 0;
    const settings = { getVersioned: async () => ({ value: '{"schemaVersion":1}', revision: '1' }), compareAndSet: async () => ({ applied: false }) } as unknown as SettingsPort;
    const health = await handleConfiguration({ action: 'health' }, { settings, fetch: async () => { providerCalls++; return new Response(); } });
    expect(health).toMatchObject({ ok: false, error: { code: 'storage_unavailable' } });
    expect(providerCalls).toBe(0);
  });

  it('TC-FND-002 produces stable opaque business identities without embedding PII', async () => {
    const index = createIndexHmacKey('identity', new Uint8Array(32).fill(5));
    const identity = { siteId: 'site_verified_001', subject: { kind: 'member' as const, id: 'site_member_001' },
      merchantId: 'configured_test_profile', environment: 'test' as const, businessReference: 'site_order_001' };
    const one = await deriveIntentId(identity, index);
    expect(one).toMatch(/^psk:v1:intents:[a-f0-9]{64}$/u);
    expect(await deriveIntentId({ ...identity }, index)).toBe(one);
    expect(one).not.toContain('site_member_001');
    expect(one).not.toContain('site_order_001');
  });

  it('TC-FND-003 rejects unsafe IDs, unknown versions and oversized records and does not retry an uncertain CAS', async () => {
    expect(() => parseStrictJson(new TextEncoder().encode('{"id":9007199254740992}'))).toThrow('UNSAFE_NUMBER');
    expect(() => assertSupportedRecord({ modelVersion: 999 })).toThrow('UNSUPPORTED_SCHEMA_VERSION');
    expect(() => assertBoundedRecord({ modelVersion: 1, value: 'x'.repeat(256 * 1024) })).toThrow('AGGREGATE_TOO_LARGE');
    let writes = 0;
    const store = { compareAndSet: async () => { writes++; throw new Error('unknown-after-commit'); } } as unknown as VersionedCollection<ModelRecord>;
    expect(await new VersionedRepository(store).create('opaque', { modelVersion: 1, state: 'pending' })).toEqual({ kind: 'unknown' });
    expect(writes).toBe(1);
  });
});
