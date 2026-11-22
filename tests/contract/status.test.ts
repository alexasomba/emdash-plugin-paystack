import { describe, expect, it } from 'vite-plus/test';
import { handleSiteStatus, safeActionErrorCode } from '../../src/routes/actions.js';
import { createFixture, invoke, invokeAction, makeTrustedBody, signedRequest } from '../support/site-admission-fixture.js';
import type { AdmissionIntentRecord } from '../../src/storage/admission.js';

async function statusFixture() {
  const fixture = await createFixture();
  const submission = makeTrustedBody();
  const admitted = await invoke(fixture.dependencies, submission, 'contract_status_admit_01');
  await invoke(fixture.dependencies, submission, 'contract_status_middle_01');
  const allocated = await invoke(fixture.dependencies, submission, 'contract_status_alloc_01');
  const intent = fixture.intents.values()[0]!;
  const attempt = intent.attempts[0]!;
  const body = { schemaVersion: '1.0', siteId: submission.siteId, subject: submission.subject,
    merchantProfile: submission.merchantProfile, intentId: intent.identityHmac, attemptId: attempt.id };
  async function status(nonce: string, overrides: Record<string, unknown> = {}) {
    const signed = await signedRequest({ ...body, ...overrides }, nonce, undefined, 'payments/status');
    return handleSiteStatus(signed.raw, signed.request, fixture.dependencies);
  }
  return { fixture, intent, attempt, body, status, admitted, allocated };
}

describe('owned payment status and action contracts', () => {
  it('TC-STA-001 keeps the admission ID stable and restricts historical status to the payment owner', async () => {
    const { fixture, intent, attempt, admitted, allocated, status } = await statusFixture();
    expect(admitted).toMatchObject({ ok: true, value: { intentId: intent.identityHmac, state: 'initializing' } });
    expect(admitted).not.toHaveProperty('value.attemptId');
    expect(allocated).toMatchObject({ ok: true, value: { intentId: intent.identityHmac, attemptId: attempt.id } });

    // A stored successor fixture exercises the read boundary independently of provider finality.
    const successorId = `psk:v1:attempts:${'d'.repeat(64)}`;
    fixture.intents.seed(intent.identityHmac, { ...intent, currentAttemptId: successorId,
      attempts: [{ ...attempt, state: 'verified_failed', providerState: 'failed' },
        { ...attempt, id: successorId, ordinal: 2, predecessorId: attempt.id }],
    } as unknown as AdmissionIntentRecord);
    expect(await status('contract_status_history_01')).toMatchObject({ ok: true, value: {
      attemptId: attempt.id, state: 'verified_failed', stage: 'complete', deliveryState: 'not_eligible',
    } });
    expect(await status('contract_status_history_02', { subject: { kind: 'member', id: 'other_member' } }))
      .toMatchObject({ ok: false, error: { code: 'forbidden' } });
  });

  it('TC-STA-002 keeps unknown and pending attempts unresolved without provider I/O', async () => {
    const { fixture, intent, attempt, status } = await statusFixture();
    for (const state of ['unknown', 'pending'] as const) {
      fixture.intents.seed(intent.identityHmac, { ...intent, state,
        attempts: [{ ...attempt, state, createTransmissionStarted: true, providerState: state }],
      } as unknown as AdmissionIntentRecord);
      expect(await status(`contract_status_${state}_001`)).toMatchObject({ ok: true, value: { state, deliveryState: 'not_eligible' } });
    }
    expect(fixture.intents.writeCount).toBe(1);
  });

  it('TC-STA-003 refuses paid state without a consistent receipt and rejects unsupported actions', async () => {
    const { fixture, intent, body, status } = await statusFixture();
    fixture.intents.seed(intent.identityHmac, { ...intent, state: 'verified_paid' } as unknown as AdmissionIntentRecord);
    expect(await status('contract_status_unproved_01')).toMatchObject({ ok: false, error: { code: 'storage_unavailable' } });
    const action = { ...body, actionId: body.attemptId, action: 'unsupported',
      siteOrigin: 'https://shop.example', callbackUrl: 'https://shop.example/payments/return' };
    expect(await invokeAction(fixture, action, 'contract_status_bad_action')).toMatchObject({ ok: false, error: { code: 'validation_error' } });
    expect(safeActionErrorCode('unsupported_action')).toBe('review_required');
  });
});
