import { describe, expect, it } from 'vite-plus/test';
import { claimSchedulerHealth, finishSchedulerHealth, readSchedulerReadiness } from '../../src/storage/scheduler-health.js';
import type { ModelRecord, VersionedCollection } from '../../src/storage/schema.js';

describe('scheduler lease', () => {
  it('rejects a completion after its lease expires and preserves a newer owner', async () => {
    let stored: { value: ModelRecord; revision: string } | null = null;
    let rev = 0;
    const collection = {
      getVersioned: async () => stored,
      compareAndSet: async (_id: string, expected: string | null, value: ModelRecord) => {
        if (expected !== (stored?.revision ?? null)) return { applied: false as const };
        stored = { value, revision: String(++rev) };
        return { applied: true as const, revision: String(rev) };
      },
    } as unknown as VersionedCollection<ModelRecord>;
    const first = await claimSchedulerHealth(collection, 'a'.repeat(32), 1_000);
    expect(first.kind).toBe('claimed');
    if (first.kind !== 'claimed') throw new Error('claim failed');
    expect(await finishSchedulerHealth(collection, first, {
      nowMs: first.lease.expiresAt, scanSucceeded: true, oldestDueAt: null,
    })).toBe(false);
    expect((await readSchedulerReadiness(collection, first.lease.expiresAt)).status).toBe('stale');
    const second = await claimSchedulerHealth(collection, 'b'.repeat(32), first.lease.expiresAt);
    expect(second.kind).toBe('claimed');
    if (second.kind !== 'claimed') throw new Error('second claim failed');
    expect(second.lease.epoch).toBe(first.lease.epoch + 1);
    expect(await finishSchedulerHealth(collection, first, {
      nowMs: first.lease.expiresAt + 1, scanSucceeded: true, oldestDueAt: null,
    })).toBe(false);
    expect(await finishSchedulerHealth(collection, second, {
      nowMs: first.lease.expiresAt + 1, scanSucceeded: true, oldestDueAt: null,
    })).toBe(true);
    expect((await readSchedulerReadiness(collection, first.lease.expiresAt + 1)).ready).toBe(true);
  });
});
