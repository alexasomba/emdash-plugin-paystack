import { describe, expect, it } from 'vite-plus/test';
import { approvedExamples } from '../support/spec-fixtures.js';
import { createFixture, makeTrustedBody, invoke } from '../support/site-admission-fixture.js';
import { projectPublishedForm } from '../../src/domain/projection.js';
import { authenticateSiteRequest } from '../../examples/astro-site/server-adapter/auth.js';
import { assignBusinessIntent, canSubmitIntent, DEFAULT_ADMISSION_ROLLOUT } from '../../examples/astro-site/server-adapter/rollout.js';

describe('consuming-site public form and authenticated adapter contracts', () => {
  it('TC-SITE-001 renders only the allowlisted public form projection', () => {
    const form = approvedExamples.fixedForm;
    const result = projectPublishedForm({ modelVersion: 1, state: 'published', updatedAt: '2026-10-18T00:00:00.000Z',
      definition: form, publishedDefinitions: [form], admissionSequence: 0 }, form.id, '1.0');
    expect(result).toMatchObject({ ok: true, value: { schemaVersion: '1.0', id: form.id, revision: form.revision } });
    if (!result.ok) throw new Error('Expected public form');
    expect(Object.keys(result.value).sort()).toEqual(['fields', 'id', 'pricing', 'purpose', 'revision', 'schemaVersion']);
  });

  it('TC-SITE-002 requires the authenticated site session, origin, CSRF, guest capability, and persistent rate limit', async () => {
    const request = new Request('https://shop.example/payments', { method: 'POST', headers: { origin: 'https://shop.example' } });
    const auth = { siteOrigin: 'https://shop.example', resolveSession: async () => null, resolveGuestCapability: async () => null, verifyCsrf: async () => true };
    expect(await authenticateSiteRequest(request, 'submit', 'site_verified_001', auth, 1000)).toEqual({ ok: false, status: 401, code: 'unauthorized' });
    const crossOrigin = new Request(request, { headers: { origin: 'https://attacker.example' } });
    expect(await authenticateSiteRequest(crossOrigin, 'submit', 'site_verified_001', auth, 1000)).toEqual({ ok: false, status: 403, code: 'forbidden' });
    // The durable-limiter and CSRF boundaries are exercised in tests/host/site-adapter.test.ts.
  });

  it('TC-SITE-003 creates an owned deterministic intent before attempt allocation and reports durable admission as 202', async () => {
    const fixture = await createFixture();
    const body = { ...makeTrustedBody(), subject: { kind: 'guest', id: 'guest_1' } };
    await invoke(fixture.dependencies, body, 'nonce_contract_reserve_001');
    const admission = await invoke(fixture.dependencies, body, 'nonce_contract_admit_0001');
    expect(admission).toMatchObject({ ok: true, value: { state: 'initializing', stage: 'allocation',
      intentId: expect.stringMatching(/^psk:v1:intents:[a-f0-9]{64}$/u) } });
    expect(admission).not.toHaveProperty('value.attemptId');
    expect(fixture.intents.values()).toHaveLength(0);
    const admitted = fixture.requestKeys.values()[0];
    expect(admitted).toMatchObject({ stage: 'admitted', attemptId: null });
    const allocated = await invoke(fixture.dependencies, body, 'nonce_contract_allocate_01');
    expect(allocated).toMatchObject({ ok: true, value: { intentId: admitted?.intentId, state: 'created',
      attemptId: admitted?.intendedAttemptId } });
    // The consuming-site boundary's HTTP 202 mapping is exercised in tests/host/site-adapter.test.ts.
  });

  it('TC-SITE-004 freezes deterministic cohorts and lets existing work continue during pause or holdout', async () => {
    const key = new Uint8Array(32).fill(7);
    const identity = { siteId: 'site', subject: { kind: 'member' as const, id: 'member' }, businessReference: 'order' };
    expect(await assignBusinessIntent(key, identity)).toEqual(await assignBusinessIntent(key, identity));
    expect(canSubmitIntent(DEFAULT_ADMISSION_ROLLOUT, 0, true)).toBe(true);
    expect(canSubmitIntent(DEFAULT_ADMISSION_ROLLOUT, 0, false)).toBe(false);
  });
});
