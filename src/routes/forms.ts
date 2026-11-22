import { hasExactKeys } from '../security/json.js';
import type { PluginContext, SandboxedRouteContext } from 'emdash/plugin';
import { FORM_MODEL_VERSION, validateFormDefinition, type FormDefinition, type FormState } from '../domain/forms.js';
import { meterCollection, StageBudget } from '../security/limits.js';
import {
	MAX_AGGREGATE_BYTES,
	isPlainObject,
	queryBounded,
	type VersionedCollection,
} from '../storage/schema.js';
import { domainError, domainOk, type DomainResult } from './response.js';

const FORM_RECORD_KEYS = ['modelVersion', 'state', 'updatedAt', 'definition', 'publishedDefinitions', 'admissionSequence'] as const;
const FORM_REVISION = /^(?:0|[1-9][0-9]*)$/u;

/** Current form state and immutable published revisions stored in one bounded CAS record. */
export interface StoredFormRecord {
	readonly modelVersion: typeof FORM_MODEL_VERSION;
	readonly state: FormState;
	readonly updatedAt: string;
	readonly definition: FormDefinition;
	readonly publishedDefinitions: readonly FormDefinition[];
	readonly admissionSequence: number;
}

export interface FormsResponse {
	readonly items?: readonly FormDefinition[];
	readonly form?: FormDefinition;
	readonly nextCursor?: string;
}

export interface FormsDependencies {
	readonly forms: VersionedCollection<StoredFormRecord>;
	readonly now?: () => number;
}

/** Revision-guarded form administration. EmDash supplies private-route auth, RBAC and CSRF. */
export async function formsRoute(routeCtx: SandboxedRouteContext, ctx: PluginContext): Promise<unknown> {
	const budget = new StageBudget('admin', () => Date.now());
	const collection = ctx.storage.forms as VersionedCollection<StoredFormRecord>;
	const forms = meterCollection(collection, budget);

	let result: DomainResult<FormsResponse>;
	try {
		result = await handleForms(routeCtx.input, { forms });
	} catch {
		result = domainError('storage_unavailable');
	}
	return result.ok ? domainOk(result.value) : domainError(result.error.code);
}

/** Domain handler kept separate so the same implementation can be exercised without a fake success path. */
export async function handleForms(input: unknown, dependencies: FormsDependencies): Promise<DomainResult<FormsResponse>> {
	try {
		if (!isPlainObject(input) || typeof input.action !== 'string') return domainError('validation_error');
		switch (input.action) {
			case 'list':
				return listForms(input, dependencies);
			case 'get':
				return getForm(input, dependencies);
			case 'save':
				return saveForm(input, dependencies);
			case 'publish':
				return transitionForm(input, dependencies, 'publish');
			case 'archive':
				return transitionForm(input, dependencies, 'archive');
			default:
				return domainError('validation_error');
		}
	} catch {
		// A rejected CAS can have an unknown commit outcome; never retry it blindly.
		return domainError('storage_unavailable');
	}
}

async function listForms(input: Record<string, unknown>, dependencies: FormsDependencies): Promise<DomainResult<FormsResponse>> {
	if (!hasExactKeys(input, ['action'], ['cursor', 'limit'])) return domainError('validation_error');
	if (input.cursor !== undefined && !isIdentifier(input.cursor)) return domainError('validation_error');
	const limit = input.limit ?? 50;
	if (!Number.isSafeInteger(limit) || typeof limit !== 'number' || limit < 1 || limit > 50) return domainError('validation_error');
	const page = await queryBounded(dependencies.forms, {
		orderBy: { updatedAt: 'desc' },
		limit,
		...(typeof input.cursor === 'string' ? { cursor: input.cursor } : {}),
	});
	const items: FormDefinition[] = [];
	for (const item of page.items) {
		const record = parseStoredForm(item.data, item.id);
		if (!record) return domainError('storage_unavailable');
		items.push(record.definition);
	}
	return domainOk({
		items: Object.freeze(items),
		...(page.hasMore && page.cursor ? { nextCursor: page.cursor } : {}),
	});
}

async function getForm(input: Record<string, unknown>, dependencies: FormsDependencies): Promise<DomainResult<FormsResponse>> {
	if (!hasExactKeys(input, ['action', 'formId']) || !isIdentifier(input.formId)) return domainError('validation_error');
	const current = await loadForm(dependencies, input.formId);
	if (current.kind === 'error') return domainError('storage_unavailable');
	if (!current.value) return domainError('form_unavailable');
	return domainOk({ form: current.value.definition });
}

async function saveForm(input: Record<string, unknown>, dependencies: FormsDependencies): Promise<DomainResult<FormsResponse>> {
	if (!hasExactKeys(input, ['action', 'definition', 'expectedRevision']) ||
		!(input.expectedRevision === null || isIdentifier(input.expectedRevision))) return domainError('validation_error');
	const candidate = validateFormDefinition(input.definition);
	if (!candidate.ok) return domainError(candidate.error);
	const formId = candidate.value.id;

	if (input.expectedRevision === null) {
		const draft = reviseDefinition(candidate.value, '1', 'draft');
		if (!draft) return domainError('review_required');
		const record = createRecord(draft, [], 0, dependencies.now);
		return createForm(formId, record, dependencies);
	}

	return mutateForm(formId, input.expectedRevision, dependencies, (current) => {
		if (current.state === 'archived') return domainError('form_unavailable');
		const revision = nextRevision(current.definition.revision);
		if (!revision) return domainError('review_required');
		const draft = reviseDefinition(candidate.value, revision, 'draft');
		if (!draft) return domainError('review_required');
		return domainOk(createRecord(draft, current.publishedDefinitions, current.admissionSequence, dependencies.now));
	});
}

async function transitionForm(
	input: Record<string, unknown>,
	dependencies: FormsDependencies,
	action: 'publish' | 'archive',
): Promise<DomainResult<FormsResponse>> {
	if (!hasExactKeys(input, ['action', 'formId', 'expectedRevision']) || !isIdentifier(input.formId) ||
		!isIdentifier(input.expectedRevision)) return domainError('validation_error');
	return mutateForm(input.formId, input.expectedRevision, dependencies, (current) => {
		if (current.state === 'archived') return domainError('form_unavailable');
		const revision = nextRevision(current.definition.revision);
		if (!revision) return domainError('review_required');
		if (action === 'archive') {
			const archived = reviseDefinition(current.definition, revision, 'archived');
			if (!archived) return domainError('review_required');
			return domainOk(createRecord(archived, current.publishedDefinitions, current.admissionSequence, dependencies.now));
		}

		if (current.state !== 'draft') return domainError('validation_error');
		const complete = validateFormDefinition(current.definition);
		if (!complete.ok) return domainError(complete.error);
		const published = reviseDefinition(complete.value, revision, 'published');
		if (!published) return domainError('review_required');
		const snapshots = Object.freeze([...current.publishedDefinitions, published]);
		return domainOk(createRecord(published, snapshots, current.admissionSequence, dependencies.now));
	});
}

async function createForm(
	formId: string,
	record: StoredFormRecord,
	dependencies: FormsDependencies,
): Promise<DomainResult<FormsResponse>> {
	if (!isWithinStorageLimit(record)) return domainError('review_required');
	try {
		const write = await dependencies.forms.compareAndSet(formId, null, record);
		if (!write.applied) return domainError('stale_revision');
		return domainOk({ form: record.definition });
	} catch {
		return domainError('storage_unavailable');
	}
}

type FormMutation = (current: StoredFormRecord) => DomainResult<StoredFormRecord>;

async function mutateForm(
	formId: string,
	expectedPublicRevision: string,
	dependencies: FormsDependencies,
	mutate: FormMutation,
): Promise<DomainResult<FormsResponse>> {
	let current = await loadForm(dependencies, formId);
	if (current.kind === 'error') return domainError('storage_unavailable');
	if (!current.value || current.value.definition.revision !== expectedPublicRevision) return domainError('stale_revision');
	let proposed = mutate(current.value);
	if (!proposed.ok) return proposed;
	if (!isWithinStorageLimit(proposed.value)) return domainError('review_required');
	try {
		const firstWrite = await dependencies.forms.compareAndSet(formId, current.storageRevision, proposed.value);
		if (firstWrite.applied) return domainOk({ form: proposed.value.definition });
	} catch {
		return domainError('storage_unavailable');
	}

	// A known CAS conflict may be admission-only. Re-read and retry once only if the public revision is unchanged.
	current = await loadForm(dependencies, formId);
	if (current.kind === 'error') return domainError('storage_unavailable');
	if (!current.value || current.value.definition.revision !== expectedPublicRevision) return domainError('stale_revision');
	proposed = mutate(current.value);
	if (!proposed.ok) return proposed;
	if (!isWithinStorageLimit(proposed.value)) return domainError('review_required');
	try {
		const retryWrite = await dependencies.forms.compareAndSet(formId, current.storageRevision, proposed.value);
		return retryWrite.applied ? domainOk({ form: proposed.value.definition }) : domainError('stale_revision');
	} catch {
		return domainError('storage_unavailable');
	}
}

type LoadedForm =
	| { readonly kind: 'loaded'; readonly value: StoredFormRecord | null; readonly storageRevision: string | null }
	| { readonly kind: 'error' };

async function loadForm(dependencies: FormsDependencies, formId: string): Promise<LoadedForm> {
	let stored: { readonly value: unknown; readonly revision: string } | null;
	try {
		stored = await dependencies.forms.getVersioned(formId);
	} catch {
		return { kind: 'error' };
	}
	if (!stored) return { kind: 'loaded', value: null, storageRevision: null };
	if (!isOpaqueRevision(stored.revision)) return { kind: 'error' };
	const record = parseStoredForm(stored.value, formId);
	return record
		? { kind: 'loaded', value: record, storageRevision: stored.revision }
		: { kind: 'error' };
}

function parseStoredForm(value: unknown, formId?: string): StoredFormRecord | null {
	if (!isPlainObject(value) || !hasExactKeys(value, FORM_RECORD_KEYS)) return null;
	if (value.modelVersion !== FORM_MODEL_VERSION || !isFormState(value.state) || !isIdentifier(value.updatedAt) ||
		!Number.isSafeInteger(value.admissionSequence) || typeof value.admissionSequence !== 'number' || value.admissionSequence < 0 ||
		!Array.isArray(value.publishedDefinitions) || value.publishedDefinitions.length > 256) return null;
	const definition = validateFormDefinition(value.definition);
	if (!definition.ok || definition.value.id !== formId && formId !== undefined || definition.value.state !== value.state) return null;
	const publishedDefinitions: FormDefinition[] = [];
	const seenRevisions = new Set<string>();
	for (const candidate of value.publishedDefinitions) {
		const snapshot = validateFormDefinition(candidate);
		if (!snapshot.ok || snapshot.value.id !== definition.value.id || snapshot.value.state !== 'published' ||
			seenRevisions.has(snapshot.value.revision)) return null;
		seenRevisions.add(snapshot.value.revision);
		publishedDefinitions.push(snapshot.value);
	}
	if (definition.value.state === 'published' && publishedDefinitions.at(-1)?.revision !== definition.value.revision) return null;
	if (serializedByteLength(value) === null || serializedByteLength(value)! > MAX_AGGREGATE_BYTES) return null;
	return Object.freeze({
		modelVersion: FORM_MODEL_VERSION,
		state: definition.value.state,
		updatedAt: value.updatedAt,
		definition: definition.value,
		publishedDefinitions: Object.freeze(publishedDefinitions),
		admissionSequence: value.admissionSequence,
	});
}

function createRecord(
	definition: FormDefinition,
	publishedDefinitions: readonly FormDefinition[],
	admissionSequence: number,
	now: () => number = () => Date.now(),
): StoredFormRecord {
	return Object.freeze({
		modelVersion: FORM_MODEL_VERSION,
		state: definition.state,
		updatedAt: new Date(now()).toISOString(),
		definition,
		publishedDefinitions: Object.freeze([...publishedDefinitions]),
		admissionSequence,
	});
}

function reviseDefinition(definition: FormDefinition, revision: string, state: FormState): FormDefinition | null {
	const result = validateFormDefinition({ ...definition, revision, state });
	return result.ok ? result.value : null;
}

function nextRevision(revision: string): string | null {
	if (!FORM_REVISION.test(revision)) return null;
	try {
		const next = (BigInt(revision) + 1n).toString();
		return next.length <= 255 ? next : null;
	} catch {
		return null;
	}
}

function isWithinStorageLimit(value: StoredFormRecord): boolean {
	const bytes = serializedByteLength(value);
	return bytes !== null && bytes <= MAX_AGGREGATE_BYTES;
}

function serializedByteLength(value: unknown): number | null {
	try {
		const serialized = JSON.stringify(value);
		return typeof serialized === 'string' ? new TextEncoder().encode(serialized).byteLength : null;
	} catch {
		return null;
	}
}


function isIdentifier(value: unknown): value is string {
	return typeof value === 'string' && value.length > 0 && Array.from(value).length <= 255 &&
		!/[\u0000-\u001f\u007f]/u.test(value);
}

function isOpaqueRevision(value: unknown): value is string {
	return typeof value === 'string' && value.length > 0 && value.length <= 255 && !/[\r\n]/u.test(value);
}

function isFormState(value: unknown): value is FormState {
	return value === 'draft' || value === 'published' || value === 'archived';
}
