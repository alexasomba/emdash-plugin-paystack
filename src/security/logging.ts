import { isSafeErrorCode, type SafeErrorCode } from '../domain/errors.js';
import { isPlainObject } from '../storage/schema.js';

export const SAFE_LOG_EVENTS = [
	'payment.admitted',
	'payment.initialize',
	'payment.verify',
	'payment.reconcile',
	'webhook.accept',
	'webhook.process',
	'result.deliver',
	'customer.map',
	'admin.access',
	'storage.failure',
	'provider.failure',
] as const;

export type SafeLogEvent = (typeof SAFE_LOG_EVENTS)[number];
export type SafeLogOutcome = 'ok' | 'pending' | 'rejected' | 'failed' | 'unknown';

export interface SafeLogRecord {
	readonly event: SafeLogEvent;
	readonly outcome: SafeLogOutcome;
	readonly environment?: 'test' | 'live';
	readonly intentId?: string;
	readonly attemptId?: string;
	readonly eventId?: string;
	readonly errorCode?: SafeErrorCode;
	readonly durationMs?: number;
}

/**
 * Make a finite log record from individually validated operational fields.
 * Message strings, provider values, customer input, references and payloads never cross this boundary.
 */
export function projectSafeLogRecord(value: unknown): SafeLogRecord | null {
	if (!isPlainObject(value) || typeof value.event !== 'string' ||
		!(SAFE_LOG_EVENTS as readonly string[]).includes(value.event)) return null;
	const record: Record<string, unknown> = {
		event: value.event,
		outcome: isOutcome(value.outcome) ? value.outcome : 'unknown',
	};
	if (value.environment === 'test' || value.environment === 'live') record.environment = value.environment;
	copyOpaqueId(value.intentId, record, 'intentId', /^psk:v1:intents:[a-f0-9]{64}$/u);
	copyOpaqueId(value.attemptId, record, 'attemptId', /^psk:v1:attempts:[a-f0-9]{64}$/u);
	copyOpaqueId(value.eventId, record, 'eventId', /^psk:v1:(?:inbox|results):[a-f0-9]{64}$/u);
	if (typeof value.errorCode === 'string' && isSafeErrorCode(value.errorCode)) record.errorCode = value.errorCode;
	if (typeof value.durationMs === 'number' && Number.isSafeInteger(value.durationMs) && value.durationMs >= 0 && value.durationMs <= 120_000) {
		record.durationMs = value.durationMs;
	}
	return Object.freeze(record) as unknown as SafeLogRecord;
}

function copyOpaqueId(value: unknown, target: Record<string, unknown>, key: 'intentId' | 'attemptId' | 'eventId', pattern: RegExp): void {
	if (typeof value === 'string' && pattern.test(value)) target[key] = value;
}

function isOutcome(value: unknown): value is SafeLogOutcome {
	return value === 'ok' || value === 'pending' || value === 'rejected' || value === 'failed' || value === 'unknown';
}
