import { describe, expect, it, vi } from 'vitest';
import { createFixture, invoke, invokeSandboxRoute, makeTrustedBody } from '../support/site-admission-fixture.js';
import { schedulerHealthId } from '../../src/storage/scheduler-health.js';

describe('scheduler admission gate', () => {
  it('admits a payment in three bounded sandbox calls', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(120_000);
    try {
      const f = await createFixture();
      const body = makeTrustedBody();
      const first = await invokeSandboxRoute(f, body, 'bounded_stage_nonce_001');
      const second = await invokeSandboxRoute(f, body, 'bounded_stage_nonce_002');
      const third = await invokeSandboxRoute(f, body, 'bounded_stage_nonce_003');
      expect(first).toMatchObject({ ok: true, value: { state: 'initializing', stage: 'admission' } });
      expect(second).toMatchObject({ ok: true, value: { state: 'initializing', stage: 'allocation' } });
      expect(third).toMatchObject({ ok: true, value: { state: 'created', stage: 'provider_work' } });
      expect(f.intents.values()).toHaveLength(1);
      expect(f.requestKeys.values()[0]?.stage).toBe('allocated');
    } finally { vi.useRealTimers(); }
  });

  it.each(['stale', 'overdue'] as const)('TC-REC-003 blocks new sandbox admissions and preserves replay when scheduler health is %s', async (condition) => {
    vi.useFakeTimers();
    vi.setSystemTime(1_200_000);
    try {
      const f = await createFixture();
      const health = f.budgets.values()[0]!;
      f.budgets.seed(schedulerHealthId(), { ...health, lastSuccessfulAt: Date.now() });
      const body = makeTrustedBody();
      for (let stage = 0; stage < 3; stage++) {
        await invokeSandboxRoute(f, body, `existing_scheduler_nonce_${stage}`);
      }
      const intent = f.intents.values()[0]!;
      const writes = [f.requestKeys.writeCount, f.intents.writeCount, f.forms.writeCount];
      f.budgets.seed(schedulerHealthId(), {
        ...health,
        lastSuccessfulAt: condition === 'stale' ? 800_000 : 1_200_000,
        oldestDueIntentAt: condition === 'overdue' ? 200_000 : null,
      });
      expect(await invokeSandboxRoute(f, { ...makeTrustedBody('new_scheduler_key'), businessReference: 'new_order' }, `blocked_${condition}_nonce_001`))
        .toMatchObject({ ok: false, error: { code: 'review_required' } });
      expect(await invokeSandboxRoute(f, body, `replay_${condition}_nonce_001`))
        .toMatchObject({ ok: true, value: { intentId: intent.identityHmac, outcome: 'existing_intent' } });
      expect([f.requestKeys.writeCount, f.intents.writeCount, f.forms.writeCount]).toEqual(writes);
    } finally { vi.useRealTimers(); }
  });

  it('pauses new admissions for stale health but permits existing payment replay', async () => {
    const f = await createFixture();
    const body = makeTrustedBody();
    for (let index = 0; index < 3; index++) {
      await invoke(f.dependencies, body, `scheduler_initial_nonce_${index}`);
    }
    const original = f.intents.values()[0];
    expect(original).toBeDefined();
    const health = f.budgets.values()[0]!;
    f.budgets.seed(schedulerHealthId(), { ...health, lastSuccessfulAt: null });
    expect(await invoke(f.dependencies, makeTrustedBody('scheduler_new_key'), 'scheduler_existing_replay_1'))
      .toMatchObject({ ok: true, value: { intentId: original!.identityHmac } });
    const fresh = makeTrustedBody('scheduler_new_intent');
    expect(await invoke(f.dependencies, { ...fresh, businessReference: 'new_order' }, 'scheduler_new_denied_1'))
      .toMatchObject({ ok: false, error: { code: 'review_required' } });
    expect(f.intents.values()).toHaveLength(1);
  });
});
