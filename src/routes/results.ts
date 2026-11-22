import type { PluginContext, SandboxedRequest, SandboxedRouteContext } from 'emdash/plugin';
import type { SettingsPort } from '../domain/configuration.js';
import { isConsistentPaidAggregate } from '../domain/verification.js';
import { isVerifiedPaymentResult } from '../domain/result.js';
import type { NonceRecord } from '../security/attestation.js';
import { compareAndSetAggregate } from '../storage/aggregates.js';
import { signInspectionCursor, verifyInspectionCursor, type InspectionCursorContext } from '../storage/cursors.js';
import { isPlainObject, type ModelRecord, type VersionedCollection } from '../storage/schema.js';
import { domainError, domainOk } from './response.js';
import { authenticatePaymentRoute } from './site.js';

const EVENT_ID = /^psk:v1:results:[a-f0-9]{64}$/u;
const CONSUMER = /^[A-Za-z0-9_-]{1,120}$/u;
export interface ResultsDependencies {
  readonly pluginId: string;
  readonly settings: SettingsPort;
  readonly nonces: Pick<VersionedCollection<NonceRecord>, 'compareAndSet'>;
  readonly intents: VersionedCollection<ModelRecord>;
  readonly now?: () => number;
}

function dependencies(ctx: PluginContext): ResultsDependencies {
  return { pluginId: ctx.plugin.id, settings: ctx.settings as unknown as SettingsPort,
    nonces: ctx.storage.nonces as unknown as VersionedCollection<NonceRecord>,
    intents: ctx.storage.intents as unknown as VersionedCollection<ModelRecord> };
}
export function resultFeedRoute(route: SandboxedRouteContext, ctx: PluginContext): Promise<unknown> {
  return handleResults('results/feed', route.input, route.request, dependencies(ctx));
}
export function resultAckRoute(route: SandboxedRouteContext, ctx: PluginContext): Promise<unknown> {
  return handleResults('results/ack', route.input, route.request, dependencies(ctx));
}

/** Authenticated fixed routes; no consumer identity is trusted from request JSON. */
export async function handleResults(route: 'results/feed' | 'results/ack', raw: unknown,
  request: SandboxedRequest, deps: ResultsDependencies): Promise<unknown> {
  const authenticated = await authenticatePaymentRoute(route, raw, request, deps);
  if (!authenticated.ok) return authenticated;
  const { body, nowMs, runtime, siteId } = authenticated.value;
  const consumerId = runtime.consumerId;
  if (!consumerId || !isPlainObject(body) || body.consumerId !== consumerId || !CONSUMER.test(consumerId)) return domainError('forbidden');
  try {
    if (route === 'results/feed') {
      if (!Object.keys(body).every((key) => ['consumerId', 'limit', 'cursor'].includes(key))) return domainError('validation_error');
      const limit = body.limit === undefined ? 50 : body.limit;
      if (typeof limit !== 'number' || !Number.isSafeInteger(limit) || limit < 1 || limit > 50) return domainError('validation_error');
      const scope: InspectionCursorContext = { siteBinding: `${siteId}/${consumerId}`, view: 'result-feed', filter: null, sort: 'verifiedAt:asc', limit };
      const keys = { activeKeyId: runtime.identityKey.keyId, keys: [runtime.identityKey] };
      let cursor: string | undefined;
      if (body.cursor !== undefined) {
        const checked = await verifyInspectionCursor(body.cursor, scope, keys, nowMs);
        if (!checked) return domainError('validation_error');
        cursor = checked;
      }
      const page = await deps.intents.query({ where: { siteId, consumerId, deliveryState: 'pending' },
        orderBy: { verifiedAt: 'asc' }, limit, ...(cursor ? { cursor } : {}) });
      const items = [];
      for (const row of page.items) {
        if (row.data.siteId !== siteId || row.data.consumerId !== consumerId || row.data.deliveryState !== 'pending' ||
          !isConsistentPaidAggregate(row.data) || !isVerifiedPaymentResult(row.data.resultEvent)) return domainError('storage_unavailable');
        items.push(row.data.resultEvent);
      }
      if (page.hasMore && !page.cursor) return domainError('storage_unavailable');
      const nextCursor = page.hasMore ? await signInspectionCursor(page.cursor!, scope, keys, nowMs) : null;
      if (page.hasMore && !nextCursor) return domainError('storage_unavailable');
      return domainOk({ items, ...(nextCursor ? { nextCursor } : {}) });
    }
    if (Object.keys(body).length !== 4 || body.schemaVersion !== '1.0' || body.outcome !== 'durably_handled' ||
      typeof body.eventId !== 'string' || !EVENT_ID.test(body.eventId)) return domainError('validation_error');
    const found = await deps.intents.query({ where: { resultEventId: body.eventId }, limit: 2 });
    if (found.items.length !== 1 || found.hasMore) return domainError('forbidden');
    const id = found.items[0]!.id;
    const stored = await deps.intents.getVersioned(id);
    if (!stored || stored.value.siteId !== siteId || stored.value.consumerId !== consumerId ||
      stored.value.resultEventId !== body.eventId || !isConsistentPaidAggregate(stored.value)) return domainError('forbidden');
    if (stored.value.deliveryState === 'acknowledged') return domainOk({ eventId: body.eventId, acknowledged: true });
    if (stored.value.deliveryState !== 'pending') return domainError('forbidden');
    const next: ModelRecord = { ...stored.value, deliveryState: 'acknowledged' };
    const result = await compareAndSetAggregate(deps.intents, id, stored.revision, next,
      (value) => value.siteId === siteId && value.consumerId === consumerId && value.resultEventId === body.eventId &&
        value.deliveryState === 'acknowledged' && isConsistentPaidAggregate(value));
    if (result.kind !== 'written') return domainError('storage_unavailable');
    return domainOk({ eventId: body.eventId, acknowledged: true });
  } catch { return domainError('storage_unavailable'); }
}
