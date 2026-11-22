import type { PersistentPaymentStore } from './persistent-store.js';

export type SiteQuota = 'mutation' | 'status' | 'feed' | 'ack' | 'public_render_ip' | 'public_render_site';
export interface QuotaResult {
	readonly allowed: boolean;
	readonly exceeded?: 'subject' | 'site' | 'consumer';
}

export interface PersistentRateLimiter {
	readonly durable: true;
	consume(input: {
		readonly quota: SiteQuota;
		readonly sitePartition: string;
		readonly subjectPartition: string;
		readonly nowMs: number;
	}): Promise<QuotaResult>;
}

const ONE_MINUTE_MS = 60_000;

/**
 * Site quotas are local, conservative defaults: mutations use the approved
 * 10/minute per subject and 60/minute per site policy; status, result feed,
 * and ACK use their separately approved per-subject/consumer quotas. Callers
 * fail closed when the configured database cannot complete an atomic counter.
 */
export function createPersistentRateLimiter(store: PersistentPaymentStore): PersistentRateLimiter {
	return Object.freeze({
		durable: true as const,
		async consume(input: {
			readonly quota: SiteQuota;
			readonly sitePartition: string;
			readonly subjectPartition: string;
			readonly nowMs: number;
		}): Promise<QuotaResult> {
			if (!store || store.durable !== true || !isDigest(input.sitePartition) ||
				!isDigest(input.subjectPartition) || !Number.isSafeInteger(input.nowMs) || input.nowMs < 0) {
				throw new Error('A configured persistent limiter is required');
			}
			const windowStartMs = Math.floor(input.nowMs / ONE_MINUTE_MS) * ONE_MINUTE_MS;
			if (input.quota === 'mutation') {
				const subjectCount = await store.consumeWindow(
					`mutation:subject:${input.subjectPartition}`,
					windowStartMs,
				);
				if (subjectCount > 10) return { allowed: false, exceeded: 'subject' };
				const siteCount = await store.consumeWindow(`mutation:site:${input.sitePartition}`, windowStartMs);
				if (siteCount > 60) return { allowed: false, exceeded: 'site' };
				return { allowed: true };
			}
			if (input.quota === 'public_render_ip') {
				const ipCount = await store.consumeWindow(`public-render:ip:${input.subjectPartition}`, windowStartMs);
				if (ipCount > 60) return { allowed: false, exceeded: 'consumer' };
				const siteCount = await store.consumeWindow(`public-render:site:${input.sitePartition}`, windowStartMs);
				return siteCount > 300 ? { allowed: false, exceeded: 'site' } : { allowed: true };
			}
			if (input.quota === 'public_render_site') {
				const siteCount = await store.consumeWindow(`public-render:site:${input.sitePartition}`, windowStartMs);
				return siteCount > 300 ? { allowed: false, exceeded: 'site' } : { allowed: true };
			}
			const limits = { status: 30, feed: 30, ack: 120 } as const;
			const count = await store.consumeWindow(`${input.quota}:${input.subjectPartition}`, windowStartMs);
			return count > limits[input.quota]
				? { allowed: false, exceeded: input.quota === 'status' ? 'subject' : 'consumer' }
				: { allowed: true };
		},
	});
}

function isDigest(value: unknown): value is string {
	return typeof value === 'string' && /^[a-f0-9]{64}$/u.test(value);
}
