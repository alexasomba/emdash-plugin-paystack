const INTENT_ID = /^psk:v1:intents:([a-f0-9]{64})$/u;
const REFERENCE = /^psk-([a-f0-9]{64})-(1|[2-9]|10)$/u;

export interface PaystackReferenceIdentity {
	readonly intentId: string;
	readonly attemptOrdinal: number;
}

/** Opaque and deterministic per intent attempt, so authenticated webhooks can find one exact intent. */
export function createPaystackReference(intentId: string, attemptOrdinal: number): string | null {
	const match = INTENT_ID.exec(intentId);
	if (!match || !Number.isSafeInteger(attemptOrdinal) || attemptOrdinal < 1 || attemptOrdinal > 10) return null;
	return `psk-${match[1]}-${attemptOrdinal}`;
}

export function parsePaystackReference(value: unknown): PaystackReferenceIdentity | null {
	if (typeof value !== 'string') return null;
	const match = REFERENCE.exec(value);
	if (!match) return null;
	const attemptOrdinal = Number(match[2]);
	if (!Number.isSafeInteger(attemptOrdinal) || attemptOrdinal < 1 || attemptOrdinal > 10) return null;
	return { intentId: `psk:v1:intents:${match[1]}`, attemptOrdinal };
}
