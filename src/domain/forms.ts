import { hasExactKeys } from '../security/json.js';
import { isPlainObject } from '../storage/schema.js';
import {
	MAX_NGN_AMOUNT_MINOR_UNITS,
	MIN_NGN_AMOUNT_MINOR_UNITS,
	parseNgnAmount,
} from './money.js';

export const FORM_SCHEMA_VERSION = '1.0' as const;
export const FORM_MODEL_VERSION = 1 as const;
export const MAX_FORM_FIELDS = 20;
export const MAX_FORM_FIELD_ID_LENGTH = 64;
export const MAX_FORM_FIELD_LABEL_LENGTH = 120;
export const MAX_FORM_FIELD_VALUE_LENGTH = 2_000;
export const MAX_FORM_METADATA_BYTES = 4 * 1024;
export const MAX_FORM_DEFINITION_BYTES = 32 * 1024;
export const MAX_FORM_SUBMISSION_BYTES = 64 * 1024;

const FIELD_ID = /^[a-z][a-z0-9_]{0,63}$/u;
const METADATA_KEY = /^[a-z][a-z0-9_-]*\.[A-Za-z0-9_.-]+$/u;
const RESERVED_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const FIELD_TYPES = ['text', 'email', 'textarea', 'select', 'checkbox'] as const;
const FORM_STATES = ['draft', 'published', 'archived'] as const;

export type FormFieldType = (typeof FIELD_TYPES)[number];
export type FormState = (typeof FORM_STATES)[number];

export interface FormFieldDefinition {
	readonly id: string;
	readonly type: FormFieldType;
	readonly label: string;
	readonly required?: boolean;
	readonly maxLength?: number;
	readonly options?: readonly string[];
}

export interface FixedPricing {
	readonly mode: 'fixed';
	readonly currency: 'NGN';
	readonly amount: string;
}

export interface TrustedOrderPricing {
	readonly mode: 'trusted_order';
	readonly currency: 'NGN';
	readonly resolution: 'site_server';
}

export interface PayerEnteredPricing {
	readonly mode: 'payer_entered';
	readonly currency: 'NGN';
	readonly minimum: string;
	readonly maximum: string;
	readonly fractionDigits: 2;
}

export type FormPricing = FixedPricing | TrustedOrderPricing | PayerEnteredPricing;

export interface FormMetadataPolicy {
	readonly allowedKeys: readonly string[];
	readonly maxBytes: number;
}

/** Public definition revision is part of the immutable form contract. */
export interface FormDefinition {
	readonly schemaVersion: typeof FORM_SCHEMA_VERSION;
	readonly id: string;
	readonly revision: string;
	readonly state: FormState;
	readonly name: string;
	readonly purpose: string;
	readonly fields: readonly FormFieldDefinition[];
	readonly pricing: FormPricing;
	readonly metadataPolicy: FormMetadataPolicy;
	readonly returnDestinationId?: string;
}

/** Storage mutations can change admissionSequence without changing the public definition revision. */
export interface StoredPaymentForm {
	readonly modelVersion: typeof FORM_MODEL_VERSION;
	readonly definition: FormDefinition;
	readonly admissionSequence: number;
}

/** EmDash CAS revision is an envelope value, never the public FormDefinition.revision. */
export interface VersionedPaymentForm {
	readonly value: StoredPaymentForm;
	readonly storageRevision: string;
}

export type FormValidationResult =
	| { readonly ok: true; readonly value: FormDefinition }
	| { readonly ok: false; readonly error: 'validation_error' | 'unsupported_schema' };

export type FieldValuesResult =
	| { readonly ok: true; readonly value: Readonly<Record<string, string | boolean>> }
	| { readonly ok: false; readonly error: 'validation_error' };

export type MetadataResult =
	| { readonly ok: true; readonly value: Readonly<Record<string, string | number | boolean | null>> }
	| { readonly ok: false; readonly error: 'validation_error' };

/** Strictly validates and freezes a supported public form definition. */
export function validateFormDefinition(input: unknown): FormValidationResult {
	if (!isPlainObject(input)) return formInvalid();
	const byteLength = serializedByteLength(input);
	if (byteLength === null || byteLength > MAX_FORM_DEFINITION_BYTES) return formInvalid();
	if (input.schemaVersion !== FORM_SCHEMA_VERSION) return formInvalid('unsupported_schema');
	if (!hasExactKeys(input, [
		'schemaVersion', 'id', 'revision', 'state', 'name', 'purpose', 'fields', 'pricing', 'metadataPolicy',
	], ['returnDestinationId'])) return formInvalid();

	if (!isIdentifier(input.id) || !isIdentifier(input.revision) || !isFormState(input.state) ||
		!isNonEmptyPlainText(input.name) || !isNonEmptyPlainText(input.purpose)) return formInvalid();
	if (input.returnDestinationId !== undefined && !isIdentifier(input.returnDestinationId)) return formInvalid();
	if (!Array.isArray(input.fields) || input.fields.length > MAX_FORM_FIELDS) return formInvalid();

	const fields: FormFieldDefinition[] = [];
	const seenFieldIds = new Set<string>();
	for (const candidate of input.fields) {
		const field = validateFieldDefinition(candidate);
		if (!field || seenFieldIds.has(field.id)) return formInvalid();
		seenFieldIds.add(field.id);
		fields.push(field);
	}

	const pricing = validatePricing(input.pricing);
	const metadataPolicy = validateMetadataPolicy(input.metadataPolicy);
	if (!pricing || !metadataPolicy) return formInvalid();

	return Object.freeze({
		ok: true,
		value: Object.freeze({
			schemaVersion: FORM_SCHEMA_VERSION,
			id: input.id,
			revision: input.revision,
			state: input.state,
			name: input.name,
			purpose: input.purpose,
			fields: Object.freeze(fields),
			pricing,
			metadataPolicy,
			...(input.returnDestinationId !== undefined ? { returnDestinationId: input.returnDestinationId } : {}),
		}),
	});
}

/** Validate declared custom-field data without coercion or accepting browser-defined fields. */
export function validateFieldValues(definition: FormDefinition, input: unknown): FieldValuesResult {
	if (!isPlainObject(input) || Object.keys(input).length > MAX_FORM_FIELDS) return fieldValuesInvalid();
	const byteLength = serializedByteLength(input);
	if (byteLength === null || byteLength > MAX_FORM_SUBMISSION_BYTES) return fieldValuesInvalid();

	const fieldsById = new Map(definition.fields.map((field) => [field.id, field]));
	const output: Record<string, string | boolean> = {};
	for (const key of Object.keys(input)) {
		if (RESERVED_KEYS.has(key)) return fieldValuesInvalid();
		const field = fieldsById.get(key);
		if (!field || !isValidFieldValue(field, input[key])) return fieldValuesInvalid();
		output[key] = input[key] as string | boolean;
	}
	for (const field of definition.fields) {
		if (field.required === true && !Object.hasOwn(input, field.id)) return fieldValuesInvalid();
	}
	return Object.freeze({ ok: true, value: Object.freeze(output) });
}

/** Validate allowlisted scalar metadata and enforce both configured and global UTF-8 byte bounds. */
export function validateFormMetadata(policy: FormMetadataPolicy, input: unknown): MetadataResult {
	if (!isPlainObject(input)) return metadataInvalid();
	const allowed = new Set(policy.allowedKeys);
	const output: Record<string, string | number | boolean | null> = {};
	for (const key of Object.keys(input)) {
		if (!allowed.has(key) || !isMetadataKey(key) || RESERVED_KEYS.has(key)) return metadataInvalid();
		const value = input[key];
		if (!(value === null || typeof value === 'string' || typeof value === 'boolean' || isSafeMetadataNumber(value))) {
			return metadataInvalid();
		}
		output[key] = value;
	}
	const byteLength = serializedByteLength(output);
	if (byteLength === null || byteLength > policy.maxBytes || byteLength > MAX_FORM_METADATA_BYTES) return metadataInvalid();
	return Object.freeze({ ok: true, value: Object.freeze(output) });
}

function validateFieldDefinition(value: unknown): FormFieldDefinition | null {
	if (!isPlainObject(value) || !hasExactKeys(value, ['id', 'type', 'label'], ['required', 'maxLength', 'options'])) return null;
	if (typeof value.id !== 'string' || !FIELD_ID.test(value.id) || RESERVED_KEYS.has(value.id)) return null;
	if (!isFormFieldType(value.type) || !isBoundedPlainText(value.label, MAX_FORM_FIELD_LABEL_LENGTH)) return null;
	if (value.required !== undefined && typeof value.required !== 'boolean') return null;
	if (value.maxLength !== undefined && (!Number.isSafeInteger(value.maxLength) ||
		typeof value.maxLength !== 'number' || value.maxLength < 1 || value.maxLength > MAX_FORM_FIELD_VALUE_LENGTH)) return null;

	let options: readonly string[] | undefined;
	if (value.options !== undefined) {
		if (!Array.isArray(value.options) || value.options.length < 1 || value.options.some((option) =>
			!isBoundedPlainText(option, MAX_FORM_FIELD_VALUE_LENGTH))) return null;
		if (new Set(value.options).size !== value.options.length) return null;
		options = Object.freeze([...value.options]);
	}
	if (value.type === 'select' && !options) return null;
	if (value.type !== 'select' && options) return null;

	return Object.freeze({
		id: value.id,
		type: value.type,
		label: value.label,
		...(value.required !== undefined ? { required: value.required } : {}),
		...(value.maxLength !== undefined ? { maxLength: value.maxLength } : {}),
		...(options ? { options } : {}),
	});
}

function validatePricing(value: unknown): FormPricing | null {
	if (!isPlainObject(value)) return null;
	if (value.mode === 'fixed') {
		if (!hasExactKeys(value, ['mode', 'currency', 'amount']) || value.currency !== 'NGN') return null;
		const amount = parseNgnAmount(value.amount);
		if (!amount.ok) return null;
		return Object.freeze({ mode: 'fixed', currency: 'NGN', amount: amount.money.value });
	}
	if (value.mode === 'trusted_order') {
		if (!hasExactKeys(value, ['mode', 'currency', 'resolution']) || value.currency !== 'NGN' || value.resolution !== 'site_server') return null;
		return Object.freeze({ mode: 'trusted_order', currency: 'NGN', resolution: 'site_server' });
	}
	if (value.mode === 'payer_entered') {
		if (!hasExactKeys(value, ['mode', 'currency', 'minimum', 'maximum', 'fractionDigits']) ||
			value.currency !== 'NGN' || value.fractionDigits !== 2) return null;
		const minimum = parseNgnAmount(value.minimum);
		const maximum = parseNgnAmount(value.maximum);
		if (!minimum.ok || !maximum.ok || minimum.money.minorUnits > maximum.money.minorUnits) return null;
		return Object.freeze({
			mode: 'payer_entered', currency: 'NGN',
			minimum: minimum.money.value, maximum: maximum.money.value, fractionDigits: 2,
		});
	}
	return null;
}

function validateMetadataPolicy(value: unknown): FormMetadataPolicy | null {
	if (!isPlainObject(value) || !hasExactKeys(value, ['allowedKeys', 'maxBytes']) ||
		!Array.isArray(value.allowedKeys) || !Number.isSafeInteger(value.maxBytes) || typeof value.maxBytes !== 'number' ||
		value.maxBytes < 1 || value.maxBytes > MAX_FORM_METADATA_BYTES) return null;
	if (value.allowedKeys.some((key) => !isMetadataKey(key)) || new Set(value.allowedKeys).size !== value.allowedKeys.length) return null;
	return Object.freeze({ allowedKeys: Object.freeze([...value.allowedKeys]), maxBytes: value.maxBytes });
}

function isValidFieldValue(field: FormFieldDefinition, value: unknown): boolean {
	if (field.type === 'checkbox') return typeof value === 'boolean';
	if (typeof value !== 'string') return false;
	const maximumLength = Math.min(field.maxLength ?? MAX_FORM_FIELD_VALUE_LENGTH, MAX_FORM_FIELD_VALUE_LENGTH);
	if (codePointLength(value) > maximumLength) return false;
	if (field.type === 'email') return value.length <= 254 && isEmailAddress(value);
	if (field.type === 'select') return field.options?.includes(value) === true;
	return true;
}

function isEmailAddress(value: string): boolean {
	if (value.length < 3 || value.length > 254 || /[\u0000-\u0020\u007f]/u.test(value)) return false;
	const separator = value.lastIndexOf('@');
	if (separator < 1 || separator === value.length - 1 || value.indexOf('@') !== separator) return false;
	const local = value.slice(0, separator);
	const domain = value.slice(separator + 1);
	if (local.length > 64 || local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false;
	if (!/^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$/u.test(local)) return false;
	const labels = domain.split('.');
	return labels.length >= 2 && labels.every((label) => label.length >= 1 && label.length <= 63 &&
		/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/u.test(label));
}

function isMetadataKey(value: unknown): value is string {
	if (typeof value !== 'string' || value.length > 255 || !METADATA_KEY.test(value)) return false;
	return !value.split('.').some((segment) => RESERVED_KEYS.has(segment));
}

function isSafeMetadataNumber(value: unknown): value is number {
	return typeof value === 'number' && Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value));
}

function isFormState(value: unknown): value is FormState {
	return typeof value === 'string' && (FORM_STATES as readonly string[]).includes(value);
}

function isFormFieldType(value: unknown): value is FormFieldType {
	return typeof value === 'string' && (FIELD_TYPES as readonly string[]).includes(value);
}

function isIdentifier(value: unknown): value is string {
	return typeof value === 'string' && value.length > 0 && codePointLength(value) <= 255 &&
		!/[\u0000-\u001f\u007f]/u.test(value);
}

function isNonEmptyPlainText(value: unknown): value is string {
	return typeof value === 'string' && value.trim().length > 0 &&
		!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value) && !containsMarkup(value);
}

function isBoundedPlainText(value: unknown, maximumLength: number): value is string {
	return typeof value === 'string' && value.trim().length > 0 && codePointLength(value) <= maximumLength &&
		!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value) && !containsMarkup(value);
}

function containsMarkup(value: string): boolean {
	return /<\s*\/?\s*[A-Za-z!][^>]*>/u.test(value);
}

function codePointLength(value: string): number {
	return Array.from(value).length;
}


function serializedByteLength(value: unknown): number | null {
	try {
		const serialized = JSON.stringify(value);
		return typeof serialized === 'string' ? new TextEncoder().encode(serialized).byteLength : null;
	} catch {
		return null;
	}
}

function formInvalid(error: 'validation_error' | 'unsupported_schema' = 'validation_error'): FormValidationResult {
	return Object.freeze({ ok: false, error });
}

function fieldValuesInvalid(): FieldValuesResult {
	return Object.freeze({ ok: false, error: 'validation_error' });
}

function metadataInvalid(): MetadataResult {
	return Object.freeze({ ok: false, error: 'validation_error' });
}

// Make the approved monetary bounds available to callers that need explicit pricing copy.
export const FORM_MINIMUM_NGN_MINOR_UNITS = MIN_NGN_AMOUNT_MINOR_UNITS;
export const FORM_MAXIMUM_NGN_MINOR_UNITS = MAX_NGN_AMOUNT_MINOR_UNITS;
