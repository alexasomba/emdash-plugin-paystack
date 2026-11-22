import { describe, expect, it } from 'vite-plus/test';
import { approvedExamples } from '../support/spec-fixtures.js';
import {
	FORM_MAXIMUM_NGN_MINOR_UNITS,
	FORM_MINIMUM_NGN_MINOR_UNITS,
	MAX_FORM_DEFINITION_BYTES,
	MAX_FORM_FIELDS,
	MAX_FORM_FIELD_ID_LENGTH,
	MAX_FORM_FIELD_LABEL_LENGTH,
	MAX_FORM_FIELD_VALUE_LENGTH,
	MAX_FORM_METADATA_BYTES,
	validateFieldValues,
	validateFormDefinition,
	validateFormMetadata,
	type FormDefinition,
	type VersionedPaymentForm,
} from '../../src/domain/forms.js';
import { formatNgnMinorUnits, parseNgnAmount } from '../../src/domain/money.js';

function definition(overrides: Partial<FormDefinition> = {}): FormDefinition {
	return {
		schemaVersion: '1.0',
		id: 'fixture_form',
		revision: 'definition-v1',
		state: 'draft',
		name: 'Fixture payment',
		purpose: 'Pay for a fixture service',
		fields: [{ id: 'payer_email', type: 'email', label: 'Email', required: true, maxLength: 254 }],
		pricing: { mode: 'fixed', currency: 'NGN', amount: '50.00' },
		metadataPolicy: { allowedKeys: ['site.campaign'], maxBytes: MAX_FORM_METADATA_BYTES },
		...overrides,
	};
}

function byteLength(value: unknown): number {
	return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

describe('exact NGN money implementation', () => {
	it('accepts inclusive form limits and preserves exact integer-kobo values', () => {
		const minimum = parseNgnAmount('50.00');
		const maximum = parseNgnAmount('1000000.00');
		expect(minimum).toMatchObject({ ok: true, money: { currency: 'NGN', value: '50.00', minorUnits: FORM_MINIMUM_NGN_MINOR_UNITS } });
		expect(maximum).toMatchObject({ ok: true, money: { currency: 'NGN', value: '1000000.00', minorUnits: FORM_MAXIMUM_NGN_MINOR_UNITS } });
		expect(formatNgnMinorUnits(FORM_MINIMUM_NGN_MINOR_UNITS)).toBe('50.00');
		expect(formatNgnMinorUnits(FORM_MAXIMUM_NGN_MINOR_UNITS)).toBe('1000000.00');
	});

	it('rejects noncanonical, exponent, non-finite, overflow, and out-of-range amounts', () => {
		for (const value of [
			'49.99', '1000000.01', '1e3', 'NaN', 'Infinity', '-Infinity', '10.001', '50', '50.0',
			'050.00', ' 50.00', '50.00 ', '999999999999999999999.00', '',
		]) {
			expect(parseNgnAmount(value).ok, value).toBe(false);
		}
		expect(formatNgnMinorUnits(-1)).toBeNull();
		expect(formatNgnMinorUnits(Number.MAX_SAFE_INTEGER + 1)).toBeNull();
	});

	it('validates all approved pricing modes without adding a donation schema alias', () => {
		for (const example of [approvedExamples.fixedForm, approvedExamples.orderForm, approvedExamples.payerEnteredForm]) {
			expect(validateFormDefinition(example).ok).toBe(true);
		}
		expect(validateFormDefinition(definition({
			pricing: { mode: 'payer_entered', currency: 'NGN', minimum: '50.00', maximum: '1000000.00', fractionDigits: 2 },
		})).ok).toBe(true);
		expect(validateFormDefinition(definition({ pricing: { mode: 'donation' } as never })).ok).toBe(false);
	});
});

describe('versioned form definition and extension boundaries', () => {
	it('accepts exactly 20 custom fields and enforces 64-character IDs and 120-character labels', () => {
		const fields = Array.from({ length: MAX_FORM_FIELDS }, (_, index) => ({
			id: `field_${index}`,
			type: 'text' as const,
			label: 'L'.repeat(MAX_FORM_FIELD_LABEL_LENGTH),
		}));
		expect(validateFormDefinition(definition({ fields })).ok).toBe(true);
		expect(validateFormDefinition(definition({ fields: [...fields, { id: 'extra', type: 'text', label: 'Extra' }] })).ok).toBe(false);

		const maximumId = `a${'b'.repeat(MAX_FORM_FIELD_ID_LENGTH - 1)}`;
		expect(validateFormDefinition(definition({ fields: [{ id: maximumId, type: 'text', label: 'Valid' }] })).ok).toBe(true);
		expect(validateFormDefinition(definition({ fields: [{ id: `${maximumId}b`, type: 'text', label: 'Too long' }] })).ok).toBe(false);
		expect(validateFormDefinition(definition({ fields: [{ id: 'long_label', type: 'text', label: `${'L'.repeat(MAX_FORM_FIELD_LABEL_LENGTH)}x` }] })).ok).toBe(false);
	});

	it('enforces 2000-character field values and declared field types', () => {
		const form = validateFormDefinition(definition({
			fields: [{ id: 'message', type: 'textarea', label: 'Message', maxLength: MAX_FORM_FIELD_VALUE_LENGTH }],
		}));
		if (!form.ok) throw new Error('fixture definition should be valid');
		expect(validateFieldValues(form.value, { message: 'x'.repeat(MAX_FORM_FIELD_VALUE_LENGTH) }).ok).toBe(true);
		expect(validateFieldValues(form.value, { message: 'x'.repeat(MAX_FORM_FIELD_VALUE_LENGTH + 1) }).ok).toBe(false);
		expect(validateFieldValues(form.value, { message: 10 }).ok).toBe(false);
		expect(validateFieldValues(form.value, { message: 'ok', unexpected: 'field' }).ok).toBe(false);
		expect(validateFieldValues(form.value, {}).ok).toBe(true);
		const requiredForm = validateFormDefinition(definition({
			fields: [{ id: 'message', type: 'textarea', label: 'Message', required: true }],
		}));
		if (!requiredForm.ok) throw new Error('required fixture definition should be valid');
		expect(validateFieldValues(requiredForm.value, {}).ok).toBe(false);
	});

	it('accepts exactly 4 KiB of allowlisted UTF-8 metadata and rejects excess or unknown keys', () => {
		const base = { 'site.campaign': '' };
		const valueAtLimit = 'x'.repeat(MAX_FORM_METADATA_BYTES - byteLength(base));
		const atLimit = { 'site.campaign': valueAtLimit };
		expect(byteLength(atLimit)).toBe(MAX_FORM_METADATA_BYTES);
		expect(validateFormMetadata({ allowedKeys: ['site.campaign'], maxBytes: MAX_FORM_METADATA_BYTES }, atLimit).ok).toBe(true);
		expect(validateFormMetadata({ allowedKeys: ['site.campaign'], maxBytes: MAX_FORM_METADATA_BYTES }, { 'site.campaign': `${valueAtLimit}x` }).ok).toBe(false);
		expect(validateFormMetadata({ allowedKeys: ['site.campaign'], maxBytes: MAX_FORM_METADATA_BYTES }, { 'site.other': 'x' }).ok).toBe(false);
		expect(validateFormMetadata({ allowedKeys: ['site.campaign'], maxBytes: MAX_FORM_METADATA_BYTES }, { 'site.campaign': ['nested'] }).ok).toBe(false);
		const multibyte = { 'site.campaign': 'é' };
		expect(validateFormMetadata({ allowedKeys: ['site.campaign'], maxBytes: byteLength(multibyte) - 1 }, multibyte).ok).toBe(false);
	});

	it('enforces the 32 KiB definition envelope and rejects unsupported or open-ended schemas', () => {
		const base = definition({ purpose: '' });
		const exactPurpose = 'x'.repeat(MAX_FORM_DEFINITION_BYTES - byteLength(base));
		expect(validateFormDefinition({ ...base, purpose: exactPurpose }).ok).toBe(true);
		expect(validateFormDefinition({ ...base, purpose: `${exactPurpose}x` }).ok).toBe(false);
		expect(validateFormDefinition({ ...base, schemaVersion: '2.0' })).toMatchObject({ ok: false, error: 'unsupported_schema' });
		expect(validateFormDefinition({ ...base, unreviewed: true }).ok).toBe(false);
	});

	it('freezes a copied public definition independently of the storage CAS revision', () => {
		const input = { ...definition(), fields: [{ id: 'note', type: 'text', label: 'Note' }] };
		const result = validateFormDefinition(input);
		if (!result.ok) throw new Error('fixture definition should be valid');
		const stored: VersionedPaymentForm = Object.freeze({
			value: Object.freeze({ modelVersion: 1 as const, definition: result.value, admissionSequence: 2 }),
			storageRevision: 'host-cas-9',
		});
		input.fields[0]!.label = 'Mutated input';
		expect(result.value.fields[0]?.label).toBe('Note');
		expect(Object.isFrozen(result.value)).toBe(true);
		expect(Object.isFrozen(result.value.fields[0])).toBe(true);
		expect(stored.value.definition.revision).toBe('definition-v1');
		expect(stored.storageRevision).toBe('host-cas-9');
	});
});
