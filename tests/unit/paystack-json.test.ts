import { describe, expect, it } from 'vite-plus/test';
import { parsePaystackJson } from '../../src/provider/paystack.js';
import { LosslessJsonNumber } from '../../src/security/json.js';

describe('bounded lossless provider JSON parsing', () => {
	it('preserves unsafe integers, fractions and exponents as exact numeric tokens', () => {
		const parsed = parsePaystackJson('{"id":9007199254740993,"fraction":1.2300,"exponent":1e+30}') as Record<string, unknown>;
		expect(parsed.id).toBeInstanceOf(LosslessJsonNumber);
		expect((parsed.id as LosslessJsonNumber).lexeme).toBe('9007199254740993');
		expect((parsed.fraction as LosslessJsonNumber).lexeme).toBe('1.2300');
		expect((parsed.exponent as LosslessJsonNumber).lexeme).toBe('1e+30');
		expect(parsed.id?.toString()).toBe('9007199254740993');
	});

	it('rejects duplicate, reserved and malformed keys before consuming provider values', () => {
		expect(() => parsePaystackJson('{"status":true,"status":false}')).toThrow('DUPLICATE_JSON_KEY');
		expect(() => parsePaystackJson('{"constructor":{}}')).toThrow('RESERVED_KEY');
		expect(() => parsePaystackJson('{"id":01}')).toThrow('INVALID_JSON');
	});
});
