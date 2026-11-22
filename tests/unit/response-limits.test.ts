import { afterEach, describe, expect, it, vi } from 'vite-plus/test';
import { domainError, domainOk, fromHostHttpJson, fromRawHostExecution, toHostEnvelope, toSiteHttpStatus } from '../../src/routes/response.js';
import { budgetLog, StageBudget, StageBudgetExceeded, waitForProvider } from '../../src/security/limits.js';

describe('typed domain and host response boundary', () => {
	it('TC-RESP-001 keeps host execution success distinct from a domain rejection', () => {
		const host = toHostEnvelope(domainError('protected_field_override'));
		expect(host.success).toBe(true);
		expect(host.data).toMatchObject({ ok: false, error: { code: 'protected_field_override' } });
		expect(toSiteHttpStatus(host.data)).toBe(422);
		expect(toSiteHttpStatus(domainError('invalid_signature'))).toBe(401);
		expect(toSiteHttpStatus(domainError('review_required'))).toBe(409);
	});

	it('TC-RESP-002 treats malformed raw and HTTP 200 host envelopes as unavailable, never paid', () => {
		for (const raw of [
			undefined,
			{ success: false, error: { code: 'internal', message: 'secret/path' } },
			{ success: true, data: { ok: 'yes', value: { status: 'verified_paid' } } },
			{ success: true, data: { ok: false, error: { code: 'unexpected', message: 'private detail' } } },
		]) {
			const result = fromRawHostExecution(raw);
			expect(result).toEqual({ ok: false, error: { code: 'provider_unavailable', message: 'Payment processing is temporarily unavailable.' } });
			expect(toSiteHttpStatus(result)).toBe(503);
		}
		const http200 = fromHostHttpJson(200, { success: true, data: { status: 'verified_paid' } });
		expect(http200).toMatchObject({ ok: false, error: { code: 'provider_unavailable' } });
		expect(fromHostHttpJson(200, { success: true, data: { ok: true, value: { status: 'verified_paid' } } }))
			.toEqual({ ok: true, value: { status: 'verified_paid' } });
		expect(fromHostHttpJson(503, { success: true, data: { ok: true, value: 'impossible' } }).ok).toBe(false);
	});

	it('TC-RESP-003 maps only the approved source aliases and emits finite static messages', () => {
		expect(fromRawHostExecution({ success: true, data: { ok: false, error: { code: 'temporary_unavailable', message: 'token abc' } } }))
			.toMatchObject({ ok: false, error: { code: 'provider_unavailable', message: 'Payment processing is temporarily unavailable.' } });
		expect(fromRawHostExecution({ success: true, data: { ok: false, error: { code: 'capacity_exceeded', message: 'private' } } }))
			.toMatchObject({ ok: false, error: { code: 'review_required' } });
	});
});

describe('stage RPC and time budgets', () => {
	let now = 100;
	afterEach(() => vi.useRealTimers());

	it('TC-RESP-004 counts each bridge call and stops before a ninth normal RPC', async () => {
		const budget = new StageBudget('provider', () => now);
		for (let index = 0; index < 8; index += 1) {
			await budget.run('storage', 'storage.read', () => index);
		}
		await expect(budget.run('http', 'http.fetch', () => 'must not run')).rejects.toMatchObject({ reason: 'rpc_limit' });
		expect(budget.count).toBe(8);
		expect(budget.snapshot.map(({ ordinal }) => ordinal)).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
		expect(budgetLog('stage_budget_stopped', 'provider', 'http.fetch', 'rpc_limit', budget)).toEqual({
			event: 'stage_budget_stopped', stage: 'provider', operation: 'http.fetch', code: 'rpc_limit', elapsedMs: 0, bridgeCalls: 8,
		});
	});

	it('TC-RESP-005 refuses settings, storage, HTTP, cron, or log work after the 20-second deadline', async () => {
		const budget = new StageBudget('reconciliation', () => now);
		await budget.run('settings', 'settings.read', () => 'bounded');
		now += 20_000;
		await expect(budget.run('cron', 'cron.schedule', () => 'must not run')).rejects.toBeInstanceOf(StageBudgetExceeded);
		expect(budget.count).toBe(1);
	});

	it('TC-RESP-006 preserves an ambiguous effect when a bridge operation returns after the self deadline', async () => {
		const budget = new StageBudget('provider', () => now);
		await expect(budget.run('http', 'http.fetch', async () => {
			now += 20_000;
			return { accepted: true };
		})).rejects.toMatchObject({ reason: 'deadline', operationStarted: true });
		expect(budget.count).toBe(1);
	});

	it('TC-RESP-007 bounds local provider wait at eight seconds without claiming request cancellation', async () => {
		vi.useFakeTimers();
		let settled = false;
		const late = new Promise<string>((resolve) => setTimeout(() => { settled = true; resolve('late provider reply'); }, 15_000));
		const waiting = waitForProvider(late);
		await vi.advanceTimersByTimeAsync(8_000);
		await expect(waiting).resolves.toEqual({ kind: 'wait_expired' });
		expect(settled).toBe(false);
		await vi.advanceTimersByTimeAsync(7_000);
		expect(settled).toBe(true);
	});
});
