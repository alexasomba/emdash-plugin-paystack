import { validateFieldValues, validateFormDefinition } from './forms.js';
import { parseNgnAmount } from './money.js';
import { decryptValue, type AesGcmEnvelope, type DataEncryptionKey } from '../security/encryption.js';
import type { AdmittedPaymentSnapshot } from '../storage/admission.js';
import { isPlainObject } from '../storage/schema.js';

/** Use the same authenticated storage domain for checkout, status, and verification. */
export async function readPaymentSnapshot(
	pluginId: string, collection: 'intents' | 'request_keys', recordId: string,
	envelope: unknown, keys: ReadonlyMap<string, DataEncryptionKey>,
): Promise<AdmittedPaymentSnapshot | null> {
	if (!isAesEnvelope(envelope)) return null;
	try {
		const value = await decryptValue<unknown>(envelope, keys, {
			pluginId, collection, recordId, schemaVersion: 1, purpose: 'custom_fields',
		});
		return isAdmittedSnapshot(value) ? value : null;
	} catch { return null; }
}

export function isAdmittedSnapshot(value: unknown): value is AdmittedPaymentSnapshot {
	return isPlainObject(value) && value.schemaVersion === '1.0' && typeof value.siteId === 'string' &&
		isPlainObject(value.subject) && (value.subject.kind === 'guest' || value.subject.kind === 'member') &&
		typeof value.subject.id === 'string' && typeof value.businessReference === 'string' &&
		typeof value.merchantProfile === 'string' && (value.environment === 'test' || value.environment === 'live') &&
		Number.isSafeInteger(value.credentialVersion) && typeof value.credentialVersion === 'number' && value.credentialVersion > 0 &&
		isPlainObject(value.amount) && value.amount.currency === 'NGN' && typeof value.amount.value === 'string' &&
		typeof value.amount.minorUnits === 'number' && isPlainObject(value.fields) && isPlainObject(value.metadata);
}

function isAesEnvelope(value: unknown): value is AesGcmEnvelope {
	return isPlainObject(value) && value.version === 1 && value.algorithm === 'A256GCM' &&
		typeof value.keyId === 'string' && typeof value.iv === 'string' && typeof value.ciphertext === 'string';
}

export function getExpectedPayment(snapshot: AdmittedPaymentSnapshot): { readonly amountMinor: number; readonly email: string } | null {
	const form = validateFormDefinition(snapshot.form);
	if (!form.ok) return null;
	const fields = validateFieldValues(form.value, snapshot.fields);
	if (!fields.ok) return null;
	const emailFields = form.value.fields.filter((field) => field.type === 'email');
	if (emailFields.length !== 1) return null;
	const email = fields.value[emailFields[0]!.id];
	const amount = snapshot.amount;
	if (typeof email !== 'string' || !isPlainObject(amount) || amount.currency !== 'NGN' ||
		!Number.isSafeInteger(amount.minorUnits) || typeof amount.minorUnits !== 'number') return null;
	const parsed = parseNgnAmount(amount.value);
	if (!parsed.ok || parsed.money.minorUnits !== amount.minorUnits) return null;
	return { amountMinor: amount.minorUnits, email };
}
