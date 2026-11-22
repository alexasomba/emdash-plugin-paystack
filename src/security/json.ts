import { StorageInvariantError } from '../storage/schema.js';

export const MAX_STRICT_JSON_BYTES = 65_536;
const RESERVED_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const MAX_DEPTH = 32;
const MAX_NODES = 4_000;

export class LosslessJsonNumber {
	constructor(readonly lexeme: string) { Object.freeze(this); }
	toString(): string { return this.lexeme; }
}

export interface StrictJsonOptions {
	/** Preserve every numeric token without converting it through IEEE-754. */
	readonly numericMode?: 'safe' | 'lossless';
}

export function parseStrictJson(
	bytes: Uint8Array,
	maxBytes = MAX_STRICT_JSON_BYTES,
	options: StrictJsonOptions = {},
): unknown {
	if (!(bytes instanceof Uint8Array) || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || bytes.byteLength > maxBytes) {
		throw new StorageInvariantError('BODY_TOO_LARGE');
	}
	let source: string;
	try {
		source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
	} catch {
		throw new StorageInvariantError('INVALID_UTF8');
	}
	let offset = 0;
	let nodes = 0;

	const fail = (): never => { throw new StorageInvariantError('INVALID_JSON'); };
	const skipWhitespace = (): void => {
		while (source[offset] === ' ' || source[offset] === '\n' || source[offset] === '\r' || source[offset] === '\t') offset += 1;
	};
	const parseString = (): string => {
		if (source[offset] !== '"') return fail();
		const start = offset;
		offset += 1;
		let escaped = false;
		while (offset < source.length) {
			const character = source[offset]!;
			if (!escaped && character === '"') {
				offset += 1;
				let decoded: unknown;
				try { decoded = JSON.parse(source.slice(start, offset)); } catch { return fail(); }
				if (typeof decoded !== 'string' || hasUnpairedSurrogate(decoded)) return fail();
				return decoded;
			}
			if (!escaped && character.charCodeAt(0) < 0x20) return fail();
			if (!escaped && character === '\\') escaped = true;
			else escaped = false;
			offset += 1;
		}
		return fail();
	};
	const parseValue = (depth: number): unknown => {
		if (depth > MAX_DEPTH || ++nodes > MAX_NODES) return fail();
		skipWhitespace();
		const character = source[offset];
		if (character === '"') return parseString();
		if (character === '{') {
			offset += 1;
			skipWhitespace();
			const output: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
			const seen = new Set<string>();
			if (source[offset] === '}') { offset += 1; return output; }
			while (offset < source.length) {
				skipWhitespace();
				const key = parseString();
				if (RESERVED_KEYS.has(key)) throw new StorageInvariantError('RESERVED_KEY');
				if (seen.has(key)) throw new StorageInvariantError('DUPLICATE_JSON_KEY');
				seen.add(key);
				skipWhitespace();
				if (source[offset] !== ':') return fail();
				offset += 1;
				output[key] = parseValue(depth + 1);
				skipWhitespace();
				if (source[offset] === '}') { offset += 1; return output; }
				if (source[offset] !== ',') return fail();
				offset += 1;
			}
			return fail();
		}
		if (character === '[') {
			offset += 1;
			skipWhitespace();
			const output: unknown[] = [];
			if (source[offset] === ']') { offset += 1; return output; }
			while (offset < source.length) {
				output.push(parseValue(depth + 1));
				skipWhitespace();
				if (source[offset] === ']') { offset += 1; return output; }
				if (source[offset] !== ',') return fail();
				offset += 1;
			}
			return fail();
		}
		if (source.startsWith('true', offset)) { offset += 4; return true; }
		if (source.startsWith('false', offset)) { offset += 5; return false; }
		if (source.startsWith('null', offset)) { offset += 4; return null; }
		const numberMatch = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(source.slice(offset));
		if (!numberMatch) return fail();
		offset += numberMatch[0].length;
		if (options.numericMode === 'lossless') return new LosslessJsonNumber(numberMatch[0]);
		const number = Number(numberMatch[0]);
		if (!Number.isFinite(number) || (Number.isInteger(number) && !Number.isSafeInteger(number))) {
			throw new StorageInvariantError('UNSAFE_NUMBER');
		}
		return number;
	};

	const value = parseValue(0);
	skipWhitespace();
	if (offset !== source.length) return fail();
	return value;
}

function hasUnpairedSurrogate(value: string): boolean {
	for (let index = 0; index < value.length; index += 1) {
		const code = value.charCodeAt(index);
		if (code >= 0xd800 && code <= 0xdbff) {
			const next = value.charCodeAt(index + 1);
			if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
			index += 1;
		} else if (code >= 0xdc00 && code <= 0xdfff) return true;
	}
	return false;
}

/** Accept only own required keys and the explicitly allowed optional keys. */
export function hasExactKeys(
	value: Record<string, unknown>,
	required: readonly string[],
	optional: readonly string[] = [],
): boolean {
	return required.every((key) => Object.hasOwn(value, key)) &&
		Object.keys(value).every((key) => required.includes(key) || optional.includes(key));
}
