import { describe, expect, it } from 'vite-plus/test';
import { createPaystackReference, parsePaystackReference } from '../../src/provider/paystack-reference.js';

const INTENT_ID = `psk:v1:intents:${'a'.repeat(64)}`;

describe('opaque deterministic Paystack references', () => {
	it('round-trips one exact intent and bounded attempt ordinal using provider-safe characters', () => {
		for (let ordinal = 1; ordinal <= 10; ordinal += 1) {
			const reference = createPaystackReference(INTENT_ID, ordinal);
			expect(reference).toMatch(/^psk-[a-f0-9]{64}-(?:[1-9]|10)$/u);
			expect(reference).toHaveLength(ordinal === 10 ? 71 : 70);
			expect(parsePaystackReference(reference)).toEqual({ intentId: INTENT_ID, attemptOrdinal: ordinal });
		}
	});

	it.each([
		['malformed intent ID', 'psk:v1:intents:raw-customer-id', 1],
		['zero ordinal', INTENT_ID, 0],
		['over-limit ordinal', INTENT_ID, 11],
		['fractional ordinal', INTENT_ID, 1.5],
	] as const)('refuses %s', (_label, intentId, ordinal) => {
		expect(createPaystackReference(intentId, ordinal)).toBeNull();
	});

	it('rejects altered, unsupported, and malformed provider references', () => {
		const reference = createPaystackReference(INTENT_ID, 4)!;
		expect(parsePaystackReference(reference)).toEqual({ intentId: INTENT_ID, attemptOrdinal: 4 });
		expect(parsePaystackReference(`${reference}x`)).toBeNull();
		expect(parsePaystackReference(reference.replace('psk-', 'other-'))).toBeNull();
		expect(parsePaystackReference(17)).toBeNull();
	});
});
