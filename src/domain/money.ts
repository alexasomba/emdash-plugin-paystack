/** NGN amounts are represented as canonical decimal strings at boundaries and integer kobo internally. */
export const NGN_MINOR_UNITS_PER_UNIT = 100;
export const MIN_NGN_AMOUNT_MINOR_UNITS = 5_000;
export const MAX_NGN_AMOUNT_MINOR_UNITS = 100_000_000;

const CANONICAL_NGN_AMOUNT = /^(?:0|[1-9][0-9]*)\.([0-9]{2})$/u;
const MAX_CANONICAL_AMOUNT_LENGTH = 10;

export interface NgnMoney {
	readonly currency: 'NGN';
	readonly value: string;
	readonly minorUnits: number;
}

export interface NgnAmountLimits {
	readonly minimumMinorUnits?: number;
	readonly maximumMinorUnits?: number;
}

export type NgnAmountResult =
	| { readonly ok: true; readonly money: NgnMoney }
	| { readonly ok: false; readonly code: 'validation_error' };

/**
 * Parse an exact two-decimal NGN amount without floating-point arithmetic.
 * The default form bounds are inclusive NGN 50.00 through NGN 1,000,000.00.
 */
export function parseNgnAmount(value: unknown, limits: NgnAmountLimits = {}): NgnAmountResult {
	if (typeof value !== 'string' || value.length > MAX_CANONICAL_AMOUNT_LENGTH) return invalidAmount();
	const match = CANONICAL_NGN_AMOUNT.exec(value);
	if (!match) return invalidAmount();

	const minimum = limits.minimumMinorUnits ?? MIN_NGN_AMOUNT_MINOR_UNITS;
	const maximum = limits.maximumMinorUnits ?? MAX_NGN_AMOUNT_MINOR_UNITS;
	if (!Number.isSafeInteger(minimum) || !Number.isSafeInteger(maximum) || minimum < 0 || maximum < minimum) {
		return invalidAmount();
	}

	const [, fraction] = match;
	const wholePart = value.slice(0, value.indexOf('.'));
	let minorUnits: bigint;
	try {
		minorUnits = BigInt(wholePart) * BigInt(NGN_MINOR_UNITS_PER_UNIT) + BigInt(fraction!);
	} catch {
		return invalidAmount();
	}
	if (minorUnits > BigInt(Number.MAX_SAFE_INTEGER) || minorUnits < BigInt(minimum) || minorUnits > BigInt(maximum)) {
		return invalidAmount();
	}

	return Object.freeze({
		ok: true,
		money: Object.freeze({ currency: 'NGN', value, minorUnits: Number(minorUnits) }),
	});
}

/** Format a non-negative, safe integer number of kobo without rounding. */
export function formatNgnMinorUnits(minorUnits: number): string | null {
	if (!Number.isSafeInteger(minorUnits) || minorUnits < 0) return null;
	const value = BigInt(minorUnits);
	const whole = value / BigInt(NGN_MINOR_UNITS_PER_UNIT);
	const fraction = String(value % BigInt(NGN_MINOR_UNITS_PER_UNIT)).padStart(2, '0');
	return `${whole}.${fraction}`;
}

function invalidAmount(): NgnAmountResult {
	return Object.freeze({ ok: false, code: 'validation_error' });
}
