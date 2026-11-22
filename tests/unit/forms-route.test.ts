import { describe, expect, it } from 'vite-plus/test';
import { validateFormDefinition, type FormDefinition } from '../../src/domain/forms.js';
import { handleForms, type StoredFormRecord } from '../../src/routes/forms.js';
import { approvedExamples } from '../support/spec-fixtures.js';
import { InMemoryFormCollection } from '../support/form-collection.js';

function definition(revision: string, state: FormDefinition['state'], overrides: Partial<FormDefinition> = {}): FormDefinition {
	const result = validateFormDefinition({ ...approvedExamples.fixedForm, revision, state, ...overrides });
	if (!result.ok) throw new Error('form route fixture is invalid');
	return result.value;
}

function record(
	current: FormDefinition = definition('7', 'published'),
	options: { readonly snapshots?: readonly FormDefinition[]; readonly admissionSequence?: number } = {},
): StoredFormRecord {
	const snapshots = options.snapshots ?? (current.state === 'published' ? [current] : []);
	return Object.freeze({
		modelVersion: 1,
		state: current.state,
		updatedAt: '2026-10-18T00:00:00.000Z',
		definition: current,
		publishedDefinitions: Object.freeze([...snapshots]),
		admissionSequence: options.admissionSequence ?? 7,
	});
}

describe('revision-guarded payment form administration', () => {
	it('creates with a null CAS expectation and refuses to overwrite an existing form', async () => {
		const forms = new InMemoryFormCollection();
		const created = await handleForms({ action: 'save', definition: approvedExamples.fixedForm, expectedRevision: null }, { forms });
		expect(created).toMatchObject({ ok: true, value: { form: { revision: '1', state: 'draft' } } });
		expect(forms.inspect('example_variable_payment')?.storageRevision).toBe('host-cas-1');
		expect(forms.compareAndSetCalls).toBe(1);

		const before = forms.inspect('example_variable_payment');
		const collision = await handleForms({
			action: 'save',
			definition: { ...approvedExamples.fixedForm, name: 'Overwritten title' },
			expectedRevision: null,
		}, { forms });
		expect(collision).toMatchObject({ ok: false, error: { code: 'stale_revision' } });
		expect(forms.inspect('example_variable_payment')?.value).toEqual(before?.value);
	});

	it('uses the public definition revision for edits while keeping the host CAS revision internal', async () => {
		const forms = new InMemoryFormCollection();
		const published = definition('7', 'published');
		forms.seed(published.id, record(published), 'host-cas-90');

		const result = await handleForms({
			action: 'save',
			definition: { ...approvedExamples.fixedForm, name: 'Updated service fee' },
			expectedRevision: '7',
		}, { forms });

		expect(result).toMatchObject({ ok: true, value: { form: { revision: '8', state: 'draft', name: 'Updated service fee' } } });
		const saved = forms.inspect(published.id);
		expect(saved?.storageRevision).not.toBe('host-cas-90');
		expect(saved?.value.admissionSequence).toBe(7);
		expect(saved?.value.publishedDefinitions.map((item) => item.revision)).toEqual(['7']);
	});

	it('re-reads and retries once after an admission-only CAS conflict without changing public revision', async () => {
		const forms = new InMemoryFormCollection();
		const published = definition('7', 'published');
		forms.seed(published.id, record(published), 'host-cas-20');
		forms.conflictOnce((current) => ({ ...current, admissionSequence: current.admissionSequence + 1 }));

		const result = await handleForms({
			action: 'save',
			definition: { ...approvedExamples.fixedForm, name: 'Changed after an admission' },
			expectedRevision: '7',
		}, { forms });

		expect(result).toMatchObject({ ok: true, value: { form: { revision: '8', state: 'draft' } } });
		expect(forms.compareAndSetCalls).toBe(2);
		expect(forms.inspect(published.id)?.value.admissionSequence).toBe(8);
		expect(forms.inspect(published.id)?.value.publishedDefinitions.map((item) => item.revision)).toEqual(['7']);
	});

	it('returns stale_revision without overwriting when the public definition changes during CAS', async () => {
		const forms = new InMemoryFormCollection();
		const published = definition('7', 'published');
		forms.seed(published.id, record(published), 'host-cas-20');
		forms.conflictOnce((current) => {
			const concurrent = definition('8', 'published', { name: 'Concurrent publish' });
			return { ...current, definition: concurrent, publishedDefinitions: [...current.publishedDefinitions, concurrent] };
		});

		const result = await handleForms({
			action: 'save',
			definition: { ...approvedExamples.fixedForm, name: 'Stale edit' },
			expectedRevision: '7',
		}, { forms });

		expect(result).toMatchObject({ ok: false, error: { code: 'stale_revision' } });
		expect(forms.compareAndSetCalls).toBe(1);
		expect(forms.inspect(published.id)?.value.definition.name).toBe('Concurrent publish');
	});

	it('does not retry a rejected CAS whose commit outcome is unknown', async () => {
		const forms = new InMemoryFormCollection();
		const published = definition('7', 'published');
		forms.seed(published.id, record(published), 'host-cas-20');
		forms.rejectNextCompareAndSet();

		const result = await handleForms({
			action: 'save',
			definition: { ...approvedExamples.fixedForm, name: 'Do not retry this write' },
			expectedRevision: '7',
		}, { forms });

		expect(result).toMatchObject({ ok: false, error: { code: 'storage_unavailable' } });
		expect(forms.compareAndSetCalls).toBe(1);
		expect(forms.inspect(published.id)?.value.definition.name).toBe(published.name);
	});

	it('publishes immutable snapshots, archives without deleting history, and returns only public definitions', async () => {
		const forms = new InMemoryFormCollection();
		const formId = 'example_variable_payment';
		const created = await handleForms({ action: 'save', definition: approvedExamples.fixedForm, expectedRevision: null }, { forms });
		expect(created).toMatchObject({ ok: true, value: { form: { revision: '1', state: 'draft' } } });

		const firstPublish = await handleForms({ action: 'publish', formId, expectedRevision: '1' }, { forms });
		expect(firstPublish).toMatchObject({ ok: true, value: { form: { revision: '2', state: 'published' } } });
		const firstSnapshot = forms.inspect(formId)?.value.publishedDefinitions[0];

		const edit = await handleForms({
			action: 'save',
			definition: { ...approvedExamples.fixedForm, name: 'Updated payment purpose' },
			expectedRevision: '2',
		}, { forms });
		expect(edit).toMatchObject({ ok: true, value: { form: { revision: '3', state: 'draft' } } });
		const secondPublish = await handleForms({ action: 'publish', formId, expectedRevision: '3' }, { forms });
		expect(secondPublish).toMatchObject({ ok: true, value: { form: { revision: '4', state: 'published' } } });

		const archived = await handleForms({ action: 'archive', formId, expectedRevision: '4' }, { forms });
		expect(archived).toMatchObject({ ok: true, value: { form: { revision: '5', state: 'archived' } } });
		const stored = forms.inspect(formId)?.value;
		expect(stored?.publishedDefinitions.map((item) => item.revision)).toEqual(['2', '4']);
		expect(stored?.publishedDefinitions[0]).toEqual(firstSnapshot);
		expect(stored?.definition.state).toBe('archived');

		const blockedSave = await handleForms({
			action: 'save', definition: approvedExamples.fixedForm, expectedRevision: '5',
		}, { forms });
		expect(blockedSave).toMatchObject({ ok: false, error: { code: 'form_unavailable' } });
		const get = await handleForms({ action: 'get', formId }, { forms });
		const list = await handleForms({ action: 'list' }, { forms });
		if (!get.ok || !get.value.form || !list.ok || !list.value.items) throw new Error('public form read should succeed');
		expect(Object.keys(get.value)).toEqual(['form']);
		expect(Object.keys(list.value)).toEqual(['items']);
		expect(get.value.form).not.toHaveProperty('publishedDefinitions');
		expect(list.value.items[0]).not.toHaveProperty('publishedDefinitions');
	});
});
