import { FORM_MODEL_VERSION, FORM_SCHEMA_VERSION, validateFormDefinition, type FormDefinition } from './forms.js';
import { isPlainObject } from '../storage/schema.js';
import { domainError, domainOk, type DomainResult } from '../routes/response.js';

export const MAX_PUBLIC_FORM_PROJECTION_BYTES = 64 * 1024;
const MAX_PUBLISHED_SNAPSHOTS = 256;

export interface PublicFormProjection {
	readonly schemaVersion: typeof FORM_SCHEMA_VERSION;
	readonly id: string;
	readonly revision: string;
	readonly purpose: string;
	readonly fields: FormDefinition['fields'];
	readonly pricing: FormDefinition['pricing'];
}

/** Build a data-only projection from a current, published stored form. */
export function readPublishedFormDefinition(
	storedValue: unknown,
	formId: string,
	schemaVersion: unknown,
): DomainResult<FormDefinition> {
	if (schemaVersion !== FORM_SCHEMA_VERSION) return domainError('unsupported_schema');
	if (!isIdentifier(formId) || !isPlainObject(storedValue) || !hasStoredFormKeys(storedValue)) {
		return domainError('storage_unavailable');
	}
	if (storedValue.modelVersion !== FORM_MODEL_VERSION ||
		storedValue.state !== 'draft' && storedValue.state !== 'published' && storedValue.state !== 'archived' ||
		typeof storedValue.updatedAt !== 'string' || !Number.isSafeInteger(storedValue.admissionSequence) ||
		typeof storedValue.admissionSequence !== 'number' || storedValue.admissionSequence < 0 ||
		!Array.isArray(storedValue.publishedDefinitions) || storedValue.publishedDefinitions.length > MAX_PUBLISHED_SNAPSHOTS) {
		return domainError('storage_unavailable');
	}
	const current = validateFormDefinition(storedValue.definition);
	if (!current.ok || current.value.id !== formId || current.value.state !== storedValue.state) {
		return domainError('storage_unavailable');
	}
	const snapshots: FormDefinition[] = [];
	const revisions = new Set<string>();
	for (const candidate of storedValue.publishedDefinitions) {
		const parsed = validateFormDefinition(candidate);
		if (!parsed.ok || parsed.value.id !== formId || parsed.value.state !== 'published' || revisions.has(parsed.value.revision)) {
			return domainError('storage_unavailable');
		}
		revisions.add(parsed.value.revision);
		snapshots.push(parsed.value);
	}
	if (current.value.state !== 'published') return domainError('form_unavailable');
	const latest = snapshots.at(-1);
	if (!latest || latest.revision !== current.value.revision || JSON.stringify(latest) !== JSON.stringify(current.value)) {
		return domainError('storage_unavailable');
	}

	return domainOk(current.value);
}

export function projectPublishedForm(
	storedValue: unknown, formId: string, schemaVersion: unknown,
): DomainResult<PublicFormProjection> {
	const current = readPublishedFormDefinition(storedValue, formId, schemaVersion);
	if (!current.ok) return current;
	const projection: PublicFormProjection = Object.freeze({
		schemaVersion: FORM_SCHEMA_VERSION,
		id: current.value.id,
		revision: current.value.revision,
		purpose: current.value.purpose,
		fields: current.value.fields,
		pricing: current.value.pricing,
	});
	let encoded: string;
	try {
		encoded = JSON.stringify(projection);
	} catch {
		return domainError('storage_unavailable');
	}
	if (new TextEncoder().encode(encoded).byteLength > MAX_PUBLIC_FORM_PROJECTION_BYTES) {
		return domainError('review_required');
	}
	return domainOk(projection);
}

function hasStoredFormKeys(value: Record<string, unknown>): boolean {
	const expected = ['modelVersion', 'state', 'updatedAt', 'definition', 'publishedDefinitions', 'admissionSequence'];
	const keys = Object.keys(value);
	return keys.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function isIdentifier(value: unknown): value is string {
	return typeof value === 'string' && value.length > 0 && value.length <= 255 && !/[\u0000-\u001f\u007f]/u.test(value);
}
