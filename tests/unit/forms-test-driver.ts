import { validateFormDefinition } from '../../src/domain/forms.js';
import { parseNgnAmount } from '../../src/domain/money.js';
import { handleForms } from '../../src/routes/forms.js';
import { InMemoryFormCollection } from '../support/form-collection.js';
import { PaymentTestDriver, type FeatureOperation, type OperationHandler } from '../support/driver.js';
import { approvedExamples } from '../support/spec-fixtures.js';

/** Bind the Red-gate operation seam to the production form handler and validators. */
export function createFormTestDriver(options: { readonly seedPublishedFixture?: boolean } = {}): PaymentTestDriver {
	const forms = new InMemoryFormCollection();
	if (options.seedPublishedFixture) {
		const parsed = validateFormDefinition({ ...approvedExamples.fixedForm, revision: '1', state: 'published' });
		if (!parsed.ok) throw new Error('approved published form fixture is invalid');
		forms.seed('example_variable_payment', Object.freeze({
			modelVersion: 1,
			state: 'published',
			updatedAt: '2026-10-18T00:00:00.000Z',
			definition: parsed.value,
			publishedDefinitions: Object.freeze([parsed.value]),
			admissionSequence: 3,
		}));
	}

	const handle = async (input: unknown): Promise<unknown> => {
		const result = await handleForms(input, { forms, now: () => Date.parse('2026-10-18T00:00:00.000Z') });
		if (!result.ok) return { ok: false, error: { code: result.error.code } };
		const form = result.value.form;
		if (!form) return { ok: false, error: { code: 'validation_error' } };
		if (isAction(input, 'archive')) {
			// The forms handler has no intent-store dependency, so archiving cannot alter historical payment state.
			return { ok: true, value: { newAdmission: form.state !== 'archived', existingIntentStatus: 'available' } };
		}
		return { ok: true, value: { formId: form.id, revision: form.revision, state: form.state } };
	};

	const handlers = new Map<FeatureOperation, OperationHandler>();
	handlers.set('form.create', async (input) => {
		if (isAction(input, 'validate')) {
			if (!isRecord(input) || !Object.hasOwn(input, 'definition')) return { ok: false, error: { code: 'validation_error' } };
			const result = validateFormDefinition(input.definition);
			return result.ok
				? { ok: true, value: { valid: true, schemaVersion: result.value.schemaVersion } }
				: { ok: false, error: { code: result.error } };
		}
		if (isAction(input, 'validate-money')) {
			if (!isRecord(input) || !Array.isArray(input.values) || input.values.some((value) => !parseNgnAmount(value).ok)) {
				return { ok: false, error: { code: 'validation_error' } };
			}
			return { ok: true, value: { valid: true } };
		}
		return handle(input);
	});
	handlers.set('form.publish', handle);
	return new PaymentTestDriver({ handlers });
}

function isAction(input: unknown, action: string): boolean {
	return isRecord(input) && input.action === action;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}
