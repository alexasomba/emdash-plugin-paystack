import { describe, expect, it } from 'vite-plus/test';
import { authenticateAndParse, canonicalAttestationFrame, verifySiteAttestation, type SiteAttestationKey } from '../../src/security/attestation.js';
import { createIndexHmacKey } from '../../src/security/encryption.js';
import { fromRawHostExecution } from '../../src/routes/response.js';
import { authenticateSiteRequest } from '../../examples/astro-site/server-adapter/auth.js';

const nowMs = Date.parse('2026-10-18T00:00:00.000Z');
const key: SiteAttestationKey = { provider: 'paystack', siteId: 'site_001', keyId: 'key_001', purpose: 'site-payment', material: new Uint8Array(32).fill(23), state: 'current' };
const hex = (bytes: Uint8Array) => [...bytes].map((v) => v.toString(16).padStart(2, '0')).join('');
async function signed(body: string, nonce: string) {
  const rawBody = new TextEncoder().encode(body);
  const bodyDigest = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', rawBody)));
  const timestampSeconds = Math.floor(nowMs / 1000);
  const frame = canonicalAttestationFrame({ siteId: key.siteId, keyId: key.keyId, timestampSeconds, nonce, method: 'POST', route: 'payments/submit', bodyDigest });
  const hmac = await crypto.subtle.importKey('raw', key.material.slice().buffer, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = hex(new Uint8Array(await crypto.subtle.sign('HMAC', hmac, new TextEncoder().encode(frame))));
  return { frame, request: { provider: 'paystack' as const, route: 'payments/submit', method: 'POST', rawBody, nowMs, keys: [key], headers: {
    'x-payment-site-id': key.siteId, 'x-payment-key-id': key.keyId, 'x-payment-timestamp': String(timestampSeconds),
    'x-payment-nonce': nonce, 'x-payment-signature': signature } } };
}
function nonces() {
  const seen = new Set<string>();
  return { async compareAndSet(id: string) { if (seen.has(id)) return { applied: false as const }; seen.add(id); return { applied: true as const, revision: '1' }; } };
}

describe('site attestation and host transport contracts', () => {
  it('TC-TRN-001 verifies the exact nine-line UTF-8 frame without a trailing LF', async () => {
    const { frame, request } = await signed('{"siteId":"site_001","amount":"50.00"}', 'bm9uY2VfMDAxX3NhbXBsZV9zaXRl');
    expect(frame.split('\n')).toHaveLength(9);
    expect(frame.endsWith('\n')).toBe(false);
    expect(await verifySiteAttestation(request)).not.toBeNull();
    expect((await authenticateAndParse(request, createIndexHmacKey('index', new Uint8Array(32).fill(24)), nonces())).ok).toBe(true);
    expect(await verifySiteAttestation({ ...request, rawBody: new TextEncoder().encode('{"siteId":"other"}') })).toBeNull();
  });

  it('TC-TRN-002 rejects duplicate JSON keys, nonce replay, stale timestamps and wrong-scope keys', async () => {
    const index = createIndexHmacKey('index', new Uint8Array(32).fill(24)), store = nonces();
    const { request } = await signed('{"siteId":"site_001"}', 'bm9uY2VfMDAxX3NhbXBsZV9zaXRl');
    expect((await authenticateAndParse(request, index, store)).ok).toBe(true);
    expect(await authenticateAndParse(request, index, store)).toEqual({ ok: false, code: 'replay' });
    expect(await verifySiteAttestation({ ...request, nowMs: nowMs + 61_000 })).toBeNull();
    expect(await verifySiteAttestation({ ...request, route: 'results/feed' })).toBeNull();
    expect(await verifySiteAttestation({ ...request, keys: [{ ...key, state: 'revoked' as const }] })).toBeNull();
    const duplicate = await signed('{"schemaVersion":"1.0","schemaVersion":"1.0"}', 'bm9uY2VfZHVwbGljYXRlX3NhbXBsZQ');
    expect(await authenticateAndParse(duplicate.request, index, store)).toEqual({ ok: false, code: 'invalid_request' });
  });

  it('TC-TRN-003 rejects malformed host envelopes and does not treat an admin cookie as site ownership', async () => {
    expect(fromRawHostExecution({ success: true, data: { ok: 'not-a-boolean', value: {} } })).toMatchObject({ ok: false });
    const request = new Request('https://shop.example/payments/status', { method: 'POST', headers: { origin: 'https://shop.example', cookie: 'admin=fixture' } });
    const auth = { siteOrigin: 'https://shop.example', resolveSession: async () => null, resolveGuestCapability: async () => null, verifyCsrf: async () => true };
    expect(await authenticateSiteRequest(request, 'status', 'site_001', auth, nowMs)).toEqual({ ok: false, status: 401, code: 'unauthorized' });
  });
});
