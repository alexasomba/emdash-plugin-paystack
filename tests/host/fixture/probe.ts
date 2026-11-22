import { pluginResponse } from 'emdash/plugin';
import type { SandboxedPlugin } from 'emdash/plugin';

export const probeRoutes: NonNullable<SandboxedPlugin['routes']> = {
  'probe/normal': {
    public: true,
    methods: ['POST'],
    request: { body: 'json', maxBytes: 512 },
    handler: async (routeCtx) => ({
      ok: true,
      value: { probe: (routeCtx.input as { probe?: unknown }).probe ?? null },
    }),
  },
  'probe/bytes': {
    public: true,
    methods: ['POST'],
    request: { body: 'bytes', maxBytes: 512, headers: ['x-paystack-signature'] },
    handler: async (routeCtx) => {
      const bytes = routeCtx.input instanceof Uint8Array ? [...routeCtx.input] : [];
      return {
        ok: true,
        value: {
          bytes,
          signature: routeCtx.request.headers['x-paystack-signature'] ?? null,
          unlisted: routeCtx.request.headers['x-unlisted-probe'] ?? null,
        },
      };
    },
  },
  'probe/private': {
    methods: ['POST'],
    request: { body: 'json', maxBytes: 512 },
    permission: 'plugins:manage',
    handler: async (routeCtx) => ({
      ok: true,
      value: { authenticated: Boolean(routeCtx.user?.id) },
    }),
  },
  'probe/raw-ack': {
    public: true,
    methods: ['POST'],
    request: { body: 'bytes', maxBytes: 512, headers: ['x-paystack-signature'] },
    response: 'raw',
    handler: async () => pluginResponse({
      status: 202,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
      body: { kind: 'text', value: 'accepted' },
    }),
  },
  'probe/budget-admission': {
    public: true,
    methods: ['POST'],
    request: { body: 'json', maxBytes: 512 },
    handler: async (_routeCtx, ctx) => {
      const operations: string[] = [];
      const storage = ctx.storage?.probe;
      if (!storage) throw new Error('Fixture storage is unavailable');
      await ctx.settings.getVersioned('probe-setting');
      operations.push('settings.getVersioned');

      const nonce = await storage.getVersioned('nonce');
      operations.push('storage.getVersioned:nonce');
      const nonceWrite = await storage.compareAndSet('nonce', nonce?.revision ?? null, { state: 'reserved' });
      if (!nonceWrite.applied) throw new Error('Fixture nonce CAS unexpectedly conflicted');
      operations.push('storage.compareAndSet:nonce');

      const quota = await storage.getVersioned('quota');
      operations.push('storage.getVersioned:quota');
      const quotaWrite = await storage.compareAndSet('quota', quota?.revision ?? null, { state: 'reserved' });
      if (!quotaWrite.applied) throw new Error('Fixture quota CAS unexpectedly conflicted');
      operations.push('storage.compareAndSet:quota-reservation');
      await storage.compareAndSet('quota', quotaWrite.revision, { state: 'cooldown' });
      operations.push('storage.compareAndSet:quota-cooldown');

      const claim = await storage.getVersioned('claim');
      operations.push('storage.getVersioned:claim');
      await storage.compareAndSet('claim', claim?.revision ?? null, { state: 'claimed' });
      operations.push('storage.compareAndSet:claim');

      return { ok: true, value: { operations, nonceApplied: nonceWrite.applied, quotaApplied: quotaWrite.applied } };
    },
  },
  'probe/budget-provider': {
    public: true,
    methods: ['POST'],
    request: { body: 'json', maxBytes: 512 },
    handler: async (_routeCtx, ctx) => {
      const operations: string[] = [];
      const storage = ctx.storage?.probe;
      if (!storage) throw new Error('Fixture storage is unavailable');
      await ctx.settings.getVersioned('probe-setting');
      operations.push('settings.getVersioned');
      await storage.query({ limit: 1 });
      operations.push('storage.query:due');
      const intent = await storage.getVersioned('intent');
      operations.push('storage.getVersioned:intent');
      const claim = await storage.compareAndSet('intent', intent?.revision ?? null, { state: 'claimed' });
      if (!claim.applied) throw new Error('Fixture claim CAS unexpectedly conflicted');
      operations.push('storage.compareAndSet:claim');
      const response = await ctx.http?.fetch('https://api.paystack.co/transaction/initialize', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      });
      operations.push('http.fetch:mocked-provider');
      await storage.compareAndSet('intent', claim.revision, { state: 'unknown-after-deadline' });
      operations.push('storage.compareAndSet:outcome');
      await storage.compareAndSet('inbox', null, { state: 'complete' });
      operations.push('storage.compareAndSet:inbox');
      ctx.log.info('Host budget fixture operation', { stage: 'provider' });
      operations.push('log.info');

      return { ok: true, value: { operations, mockedStatus: response?.status ?? null } };
    },
  },
  'probe/denied-host': {
    public: true,
    methods: ['POST'],
    request: { body: 'json', maxBytes: 512 },
    handler: async (_routeCtx, ctx) => {
      try {
        await ctx.http?.fetch('https://undeclared.example.invalid/should-not-connect', { method: 'GET' });
        return { ok: true, value: { blocked: false } };
      } catch {
        return { ok: true, value: { blocked: true } };
      }
    },
  },
};
