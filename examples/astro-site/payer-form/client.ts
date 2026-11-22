export type PublicFormField = {
	readonly id: string;
	readonly type: 'text' | 'email' | 'textarea' | 'select' | 'checkbox';
	readonly label: string;
	readonly required?: boolean;
	readonly maxLength?: number;
	readonly options?: readonly string[];
};

export type PublicFormPricing =
	| { readonly mode: 'fixed'; readonly currency: 'NGN'; readonly amount: string }
	| { readonly mode: 'trusted_order'; readonly currency: 'NGN'; readonly resolution: 'site_server' }
	| { readonly mode: 'payer_entered'; readonly currency: 'NGN'; readonly minimum: string; readonly maximum: string; readonly fractionDigits: 2 };

export interface BrowserPaymentSubmission {
	readonly schemaVersion: '1.0';
	readonly formId: string;
	readonly formRevision: string;
	readonly requestKey: string;
	readonly fields: Readonly<Record<string, string | boolean>>;
	readonly payerAmount?: string;
}

export interface RecoveryDraft {
	readonly version: 1;
	readonly savedAt: number;
	readonly submission: BrowserPaymentSubmission;
	readonly intentId?: string;
	readonly attemptId?: string;
}

export type RecoveryRequest =
	| { readonly operation: 'submit'; readonly body: BrowserPaymentSubmission }
	| { readonly operation: 'status'; readonly body: { readonly schemaVersion: '1.0'; readonly intentId: string; readonly attemptId?: string } };

const DRAFT_TTL_MS = 30 * 60 * 1000;

export function validateEnterAmount(value: string, minimum: string, maximum: string): boolean {
	const amount = toMinorUnits(value);
	const min = toMinorUnits(minimum);
	const max = toMinorUnits(maximum);
	return amount !== null && min !== null && max !== null && min <= max && amount >= min && amount <= max;
}

/** Build only the public form contract; unknown/protected browser keys are never copied. */
export function buildSubmission(input: {
	readonly formId: string;
	readonly formRevision: string;
	readonly requestKey: string;
	readonly fields: readonly PublicFormField[];
	readonly values: Readonly<Record<string, unknown>>;
	readonly pricing: PublicFormPricing;
}): BrowserPaymentSubmission | null {
	if (!isIdentifier(input.formId) || !isIdentifier(input.formRevision) || !isRequestKey(input.requestKey)) return null;
	const fields: Record<string, string | boolean> = Object.create(null) as Record<string, string | boolean>;
	for (const definition of input.fields) {
		if (!isIdentifier(definition.id) || !Object.hasOwn(input.values, definition.id)) continue;
		const value = input.values[definition.id];
		if (definition.type === 'checkbox') {
			if (typeof value !== 'boolean') return null;
			fields[definition.id] = value;
		} else {
			if (typeof value !== 'string' || value.length > (definition.maxLength ?? 2_000)) return null;
			if (definition.type === 'select' && !definition.options?.includes(value)) return null;
			fields[definition.id] = value;
		}
	}
	if (input.fields.some((field) => field.required === true && !Object.hasOwn(fields, field.id))) return null;
	if (input.pricing.mode === 'payer_entered') {
		const payerAmount = input.values.payerAmount;
		if (typeof payerAmount !== 'string' || !validateEnterAmount(payerAmount, input.pricing.minimum, input.pricing.maximum)) return null;
		return Object.freeze({
			schemaVersion: '1.0', formId: input.formId, formRevision: input.formRevision,
			requestKey: input.requestKey, fields: Object.freeze(fields), payerAmount,
		});
	}
	if (Object.hasOwn(input.values, 'payerAmount')) return null;
	return Object.freeze({
		schemaVersion: '1.0', formId: input.formId, formRevision: input.formRevision,
		requestKey: input.requestKey, fields: Object.freeze(fields),
	});
}

export function getOrCreateRequestKey(
	storage: Pick<Storage, 'getItem' | 'setItem'> | null,
	formId: string,
	formRevision: string,
	randomId: () => string = () => globalThis.crypto.randomUUID(),
): { readonly requestKey: string; readonly persisted: boolean } {
	const storageKey = requestKeyStorageKey(formId, formRevision);
	if (storage) {
		try {
			const existing = storage.getItem(storageKey);
			if (isRequestKey(existing)) return { requestKey: existing, persisted: true };
		} catch {
			// Storage may be disabled by browser policy; this tab still keeps one in-memory key.
		}
	}
	const requestKey = randomId();
	if (!isRequestKey(requestKey)) throw new Error('A UUID request key is required');
	if (storage) {
		try {
			storage.setItem(storageKey, requestKey);
			return { requestKey, persisted: true };
		} catch {
			// Keep the key in memory and let the UI explain that reload recovery is unavailable.
		}
	}
	return { requestKey, persisted: false };
}

export function clearRequestKey(storage: Pick<Storage, 'removeItem'> | null, formId: string, formRevision: string): void {
	try { storage?.removeItem(requestKeyStorageKey(formId, formRevision)); } catch { /* Storage is optional. */ }
}

export function readRecoveryDraft(
	storage: Pick<Storage, 'getItem' | 'removeItem'> | null,
	formId: string,
	formRevision: string,
	nowMs = Date.now(),
): RecoveryDraft | null {
	if (!storage) return null;
	const key = recoveryStorageKey(formId, formRevision);
	try {
		const serialized = storage.getItem(key);
		if (!serialized || serialized.length > 32_768) return null;
		const value: unknown = JSON.parse(serialized);
		if (!isPlainObject(value) || value.version !== 1 || !Number.isSafeInteger(value.savedAt) ||
			typeof value.savedAt !== 'number' || value.savedAt > nowMs || nowMs - value.savedAt > DRAFT_TTL_MS ||
			!isValidSubmission(value.submission, formId, formRevision) ||
			(value.intentId !== undefined && !isPaymentIntentId(value.intentId)) ||
			(value.attemptId !== undefined && !isPaymentAttemptId(value.attemptId)) ||
			(value.attemptId !== undefined && value.intentId === undefined)) {
			storage.removeItem(key);
			return null;
		}
		return value as unknown as RecoveryDraft;
	} catch {
		return null;
	}
}

export function saveRecoveryDraft(
	storage: Pick<Storage, 'setItem'> | null,
	submission: BrowserPaymentSubmission,
	nowMs = Date.now(),
	reference?: { readonly intentId: string; readonly attemptId?: string },
): boolean {
	if (!storage || !isValidSubmission(submission, submission.formId, submission.formRevision) ||
		(reference !== undefined && !isPaymentReference(reference))) return false;
	try {
		storage.setItem(recoveryStorageKey(submission.formId, submission.formRevision), JSON.stringify({
			version: 1, savedAt: nowMs, submission,
			...(reference ? { intentId: reference.intentId, ...(reference.attemptId ? { attemptId: reference.attemptId } : {}) } : {}),
		} satisfies RecoveryDraft));
		return true;
	} catch {
		return false;
	}
}

/** Resume the original admission until an attempt exists, then query that owned attempt. */
export function buildRecoveryRequest(draft: RecoveryDraft): RecoveryRequest {
	if (isPaymentIntentId(draft.intentId) && isPaymentAttemptId(draft.attemptId)) {
		return {
			operation: 'status',
			body: {
				schemaVersion: '1.0', intentId: draft.intentId,
				attemptId: draft.attemptId,
			},
		};
	}
	return { operation: 'submit', body: draft.submission };
}

export function clearRecoveryDraft(storage: Pick<Storage, 'removeItem'> | null, formId: string, formRevision: string): void {
	try { storage?.removeItem(recoveryStorageKey(formId, formRevision)); } catch { /* Storage is optional. */ }
}

export function safeCheckoutDestination(value: unknown): string | null {
	if (typeof value !== 'string') return null;
	try {
		const url = new URL(value);
		return url.origin === 'https://checkout.paystack.com' && !url.username && !url.password ? url.href : null;
	} catch {
		return null;
	}
}

function readPaymentReference(value: Record<string, unknown>): { readonly intentId: string; readonly attemptId?: string } | null {
	if (!isPaymentIntentId(value.intentId) || (value.attemptId !== undefined && !isPaymentAttemptId(value.attemptId))) return null;
	return {
		intentId: value.intentId,
		...(typeof value.attemptId === 'string' ? { attemptId: value.attemptId } : {}),
	};
}

/** Attach the same-origin consuming-site form; the browser never calls EmDash directly. */
export function attachPaymentForm(form: HTMLFormElement | null): void {
	if (!form) return;
	const formId = form.dataset.formId;
	const formRevision = form.dataset.formRevision;
	const schemaVersion = form.dataset.formSchema;
	const endpoint = sameOriginEndpoint(form.dataset.submitEndpoint);
	const actionEndpoint = sameOriginEndpoint(form.dataset.actionEndpoint);
	const statusEndpoint = sameOriginEndpoint(form.dataset.statusEndpoint);
	const csrfToken = form.dataset.csrfToken;
	const pricingMode = form.dataset.pricingMode;
	if (!isIdentifier(formId) || !isIdentifier(formRevision) || schemaVersion !== '1.0' || !endpoint || !actionEndpoint || !statusEndpoint ||
		typeof csrfToken !== 'string' || csrfToken.length < 1 ||
		!['fixed', 'trusted_order', 'payer_entered'].includes(String(pricingMode))) {
		showStaticError(form, 'This payment form is not configured correctly. Please contact the site administrator.');
		return;
	}
	const activeForm = form;
	const activeFormId = formId;
	const activeFormRevision = formRevision;
	const activeEndpoint = endpoint;
	const activeActionEndpoint = actionEndpoint;
	const activeStatusEndpoint = statusEndpoint;
	const activeCsrfToken = csrfToken;
	setPaymentFormLocked(activeForm, false);
	const storage = getSessionStorage();
	const key = getOrCreateRequestKey(storage, activeFormId, activeFormRevision);
	let activeRequestKey = key.requestKey;
	const definitions = readFieldDefinitions(activeForm);
	const pricing: PublicFormPricing = pricingMode === 'payer_entered'
		? { mode: 'payer_entered', currency: 'NGN', minimum: form.dataset.minimum ?? '', maximum: form.dataset.maximum ?? '', fractionDigits: 2 }
		: pricingMode === 'trusted_order'
			? { mode: 'trusted_order', currency: 'NGN', resolution: 'site_server' }
			: { mode: 'fixed', currency: 'NGN', amount: '0' };
	const status = activeForm.parentElement?.querySelector<HTMLElement>('#payment-status') ?? null;
	const error = activeForm.querySelector<HTMLElement>('#form-error');
	const recoveryPanel = activeForm.parentElement?.querySelector<HTMLElement>('#recovery-panel') ?? null;
	const reconcile = recoveryPanel?.querySelector<HTMLButtonElement>('[data-reconcile]') ?? null;
	const submitButton = activeForm.querySelector<HTMLButtonElement>('[data-submit]');
	let busy = false;
	let pendingSubmission: BrowserPaymentSubmission | null = null;
	let pendingReference: { readonly intentId: string; readonly attemptId?: string } | undefined;
	let terminal = false;
	if (reconcile) reconcile.disabled = false;

	const recovered = readRecoveryDraft(storage, activeFormId, activeFormRevision);
	if (recovered) {
		pendingSubmission = recovered.submission;
		pendingReference = recovered.intentId
			? { intentId: recovered.intentId, ...(recovered.attemptId ? { attemptId: recovered.attemptId } : {}) }
			: undefined;
		fillFields(activeForm, recovered.submission);
		setPaymentFormLocked(activeForm, true);
		setRecoveryVisible(recoveryPanel, true);
		setStatus(status, 'A previous payment has an unresolved outcome. Check that same payment before trying again.');
	} else if (!key.persisted) {
		setStatus(status, 'This browser cannot retain a request key across reloads. Keep this page open while checking an uncertain payment.');
	}

	form.addEventListener('submit', (event) => {
		event.preventDefault();
		if (busy || pendingSubmission) return;
		if (!activeForm.reportValidity()) {
			focusFirstInvalid(activeForm);
			return;
		}
		const submission = collectSubmission(activeForm, {
			formId: activeFormId, formRevision: activeFormRevision, requestKey: activeRequestKey, fields: definitions, pricing,
		});
		if (!submission) {
			showFormError(activeForm, error, 'Check the required fields and amount limits before continuing.');
			return;
		}
		void submitExisting(submission);
	});

	reconcile?.addEventListener('click', () => {
		if (pendingSubmission && !busy) void checkExistingPayment();
	});

	async function submitExisting(submission: BrowserPaymentSubmission): Promise<void> {
		await sendSiteRequest(activeEndpoint, submission, submission, 'initial');
	}

	async function checkExistingPayment(): Promise<void> {
		if (!pendingSubmission) return;
		const draft: RecoveryDraft = {
			version: 1, savedAt: Date.now(), submission: pendingSubmission,
			...(pendingReference ? {
				intentId: pendingReference.intentId,
				...(pendingReference.attemptId ? { attemptId: pendingReference.attemptId } : {}),
			} : {}),
		};
		const recoveryRequest = buildRecoveryRequest(draft);
		const target = recoveryRequest.operation === 'status' ? activeStatusEndpoint : activeEndpoint;
		await sendSiteRequest(target, recoveryRequest.body, pendingSubmission, 'recovery');
	}

	async function sendSiteRequest(
		target: string,
		body: BrowserPaymentSubmission | { readonly schemaVersion: '1.0'; readonly intentId: string; readonly attemptId?: string },
		submission: BrowserPaymentSubmission,
		mode: 'initial' | 'recovery',
	): Promise<void> {
		if (navigator.onLine === false) {
			if (mode === 'recovery') {
				setRecoveryVisible(recoveryPanel, true);
				setStatus(status, 'You are offline. No status request was sent; reconnect and check this same payment.');
			} else {
				showFormError(activeForm, error, 'You are offline, so no payment request was sent. Reconnect before continuing.');
			}
			return;
		}
		pendingSubmission = submission;
		setPaymentFormLocked(activeForm, true);
		const persisted = saveRecoveryDraft(storage, submission, Date.now(), pendingReference);
		busy = true;
		if (submitButton) submitButton.disabled = true;
		if (reconcile) reconcile.disabled = true;
		if (error) error.hidden = true;
		setStatus(status, mode === 'recovery' ? 'Checking this existing payment with the site…' : 'Sending this payment request to the site…');
		setRecoveryVisible(recoveryPanel, mode === 'recovery');
		if (!persisted) setStatus(status, mode === 'recovery'
			? 'Checking this existing payment. Keep this page open; browser storage is unavailable for reload recovery.'
			: 'Sending this payment request. Keep this page open; browser storage is unavailable for reload recovery.');
		try {
			const response = await fetch(target, {
				method: 'POST',
				credentials: 'same-origin',
				cache: 'no-store',
				headers: { 'content-type': 'application/json', 'x-csrf-token': activeCsrfToken },
				body: JSON.stringify(body),
			});
			let payload: unknown = await response.json();
			if (!response.ok) {
				handleSiteError(response.status, payload, submission, mode);
				return;
			}
			const result = parseSitePaymentStatus(payload);
			const reference = result ? readPaymentReference(result) : null;
			if (reference) {
				pendingReference = reference;
				saveRecoveryDraft(storage, submission, Date.now(), reference);
			}
			const action = buildCreatedPaymentAction(result);
			if (action) {
				setStatus(status, 'Preparing the secure Paystack checkout for this payment…');
				const actionResponse = await fetch(activeActionEndpoint, { method: 'POST', credentials: 'same-origin', cache: 'no-store',
					headers: { 'content-type': 'application/json', 'x-csrf-token': activeCsrfToken }, body: JSON.stringify(action) });
				payload = await actionResponse.json();
				if (!actionResponse.ok) { handleSiteError(actionResponse.status, payload, submission, 'recovery'); return; }
				const actionResult = parseSitePaymentStatus(payload);
				if (!actionResult || actionResult.intentId !== action.intentId || actionResult.attemptId !== action.attemptId) {
					throw new Error('Payment action identity mismatch');
				}
			}
			handlePaymentResult(payload, submission);
		} catch {
			pendingSubmission = submission;
			setRecoveryVisible(recoveryPanel, true);
			setStatus(status, persisted
				? 'The site could not confirm the result. Your details and request key are saved in this tab; check the same payment before doing anything else.'
				: 'The site could not confirm the result and browser storage is unavailable. Keep this page open and check the same payment before doing anything else.');
		} finally {
			busy = false;
			setPaymentFormLocked(activeForm, terminal || pendingSubmission !== null);
			if (reconcile) reconcile.disabled = terminal;
		}
	}

	function handlePaymentResult(payload: unknown, submission: BrowserPaymentSubmission): void {
		const result = parseSitePaymentStatus(payload);
		if (!result) {
			pendingSubmission = submission;
			setRecoveryVisible(recoveryPanel, true);
			setStatus(status, 'The site returned an unrecognized payment state. Treat the outcome as unresolved and check the same payment again.');
			return;
		}
		const stateName = result.state;
		if (isSafeNextAction(result.nextAction)) {
			setStatus(status, 'Opening the secure Paystack checkout for this payment.');
			globalThis.location.assign(result.nextAction.destination);
			return;
		}
		if (stateName === 'verified_paid') {
			terminal = true;
			clearRecoveryDraft(storage, activeFormId, activeFormRevision);
			clearRequestKey(storage, activeFormId, activeFormRevision);
			pendingSubmission = null;
			setRecoveryVisible(recoveryPanel, false);
			setStatus(status, 'Payment verified. The consuming site will confirm what happens next.');
			disablePaymentForm(activeForm, 'This payment has been verified.');
			return;
		}
		if (stateName === 'verified_failed' || stateName === 'verified_canceled') {
			terminal = true;
			clearRecoveryDraft(storage, activeFormId, activeFormRevision);
			clearRequestKey(storage, activeFormId, activeFormRevision);
			pendingSubmission = null;
			setRecoveryVisible(recoveryPanel, false);
			setStatus(status, stateName === 'verified_canceled'
				? 'This payment was canceled. The site must authorize any separate payment.'
				: 'This attempt was not paid. The site must authorize any retry; no new payment was started.');
			disablePaymentForm(activeForm, 'This attempt is finished.');
			return;
		}
		pendingSubmission = submission;
		setRecoveryVisible(recoveryPanel, true);
		const messages: Readonly<Record<string, string>> = {
			created: 'This payment is created and awaiting provider initialization. Check this same payment again.',
			initializing: 'The site is still initializing this payment. Check this same payment again; no second payment was started.',
			requires_action: 'This payment needs an additional action. Check the same payment to continue securely.',
			pending: 'The provider has not confirmed a final outcome. Check this same payment again.',
			unknown: 'The payment outcome is unknown. The site must reconcile this same payment before any retry.',
			review_required: 'This payment needs operator review. Do not start another payment for this request.',
		};
		setStatus(status, messages[String(stateName)] ?? 'Payment is unresolved. Check this existing payment again; do not submit a new one.');
	}

	function handleSiteError(httpStatus: number, payload: unknown, submission: BrowserPaymentSubmission, mode: 'initial' | 'recovery'): void {
		const code = isPlainObject(payload) && typeof payload.code === 'string' ? payload.code : '';
		if (httpStatus === 401 || httpStatus === 403 || code === 'unauthorized' || code === 'forbidden') {
			if (mode === 'initial') {
				clearRecoveryDraft(storage, activeFormId, activeFormRevision);
				pendingSubmission = null;
				setPaymentFormLocked(activeForm, false);
				setRecoveryVisible(recoveryPanel, false);
				showFormError(activeForm, error, 'The site denied this request before accepting a payment. Sign in or contact the site administrator.');
			} else {
				setStatus(status, 'Permission was denied. Sign in or contact the site administrator. This payment remains unresolved.');
				setRecoveryVisible(recoveryPanel, true);
				pendingSubmission = submission;
			}
			return;
		}
		if (code === 'validation_error' || code === 'unsupported_schema' || code === 'protected_field_override' || code === 'form_unavailable') {
			if (mode === 'recovery') {
				setStatus(status, 'The site could not validate this recovery request. Keep this payment unresolved and contact the site before trying again.');
				setRecoveryVisible(recoveryPanel, true);
				pendingSubmission = submission;
				return;
			}
			clearRecoveryDraft(storage, activeFormId, activeFormRevision);
			pendingSubmission = null;
			clearRequestKey(storage, activeFormId, activeFormRevision);
			activeRequestKey = getOrCreateRequestKey(storage, activeFormId, activeFormRevision).requestKey;
			setPaymentFormLocked(activeForm, false);
			setRecoveryVisible(recoveryPanel, false);
			showFormError(activeForm, error, 'The site rejected these form details. Review the fields and try again.');
			return;
		}
		if (isPlainObject(payload) && payload.state === 'review_required') {
			setStatus(status, 'This payment needs operator review. Do not start another payment for this request.');
		} else if (code === 'review_required') {
			if (mode === 'initial') {
				clearRecoveryDraft(storage, activeFormId, activeFormRevision);
				pendingSubmission = null;
				clearRequestKey(storage, activeFormId, activeFormRevision);
				activeRequestKey = getOrCreateRequestKey(storage, activeFormId, activeFormRevision).requestKey;
				setPaymentFormLocked(activeForm, false);
				setRecoveryVisible(recoveryPanel, false);
				showFormError(activeForm, error, 'New payment admission is paused by the site. Your details are retained; try again only after the site reopens payments.');
				return;
			}
			setStatus(status, 'New payment admission is paused by the site. Existing payments remain available for status checks.');
		} else if (code === 'rate_limited' && mode === 'initial') {
			clearRecoveryDraft(storage, activeFormId, activeFormRevision);
			pendingSubmission = null;
			clearRequestKey(storage, activeFormId, activeFormRevision);
			activeRequestKey = getOrCreateRequestKey(storage, activeFormId, activeFormRevision).requestKey;
			setPaymentFormLocked(activeForm, false);
			setRecoveryVisible(recoveryPanel, false);
			showFormError(activeForm, error, 'The site is limiting new payment requests. This request was not accepted; try again when the site allows it.');
			return;
		} else if (code === 'rate_limited') {
			setStatus(status, 'The site is temporarily limiting requests. Wait, then check this same payment.');
		} else {
			setStatus(status, 'The site could not confirm the payment outcome. Keep the request key and check this same payment again.');
		}
		setRecoveryVisible(recoveryPanel, true);
		pendingSubmission = submission;
	}
}

function collectSubmission(
	form: HTMLFormElement,
	input: Omit<Parameters<typeof buildSubmission>[0], 'values'>,
): BrowserPaymentSubmission | null {
	const values: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
	for (const definition of input.fields) {
		const element = form.elements.namedItem(definition.id);
		if (element instanceof HTMLInputElement && definition.type === 'checkbox') values[definition.id] = element.checked;
		else if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement) {
			values[definition.id] = element.value;
		}
	}
	const amount = form.elements.namedItem('payerAmount');
	if (amount instanceof HTMLInputElement) values.payerAmount = amount.value.trim();
	return buildSubmission({ ...input, values });
}

function readFieldDefinitions(form: HTMLFormElement): PublicFormField[] {
	const definitions: PublicFormField[] = [];
	for (const element of Array.from(form.elements)) {
		if (!(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement) ||
			!element.name || element.name === 'payerAmount') continue;
		const label = form.querySelector<HTMLLabelElement>(`label[for="${CSS.escape(element.id)}"]`);
		const type: PublicFormField['type'] = element instanceof HTMLTextAreaElement ? 'textarea' :
			element instanceof HTMLSelectElement ? 'select' : element.type === 'checkbox' ? 'checkbox' : element.type === 'email' ? 'email' : 'text';
		definitions.push({
			id: element.name, type, label: label?.textContent?.trim() ?? element.name,
			required: element.required,
			...(type === 'select' ? { options: Array.from((element as HTMLSelectElement).options).map((option) => option.value).filter(Boolean) } : {}),
			...('maxLength' in element && element.maxLength > 0 ? { maxLength: element.maxLength } : {}),
		});
	}
	return definitions;
}

function fillFields(form: HTMLFormElement, submission: BrowserPaymentSubmission): void {
	for (const [name, value] of Object.entries(submission.fields)) {
		const element = form.elements.namedItem(name);
		if (element instanceof HTMLInputElement && element.type === 'checkbox' && typeof value === 'boolean') element.checked = value;
		else if ((element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement) && typeof value === 'string') {
			element.value = value;
		}
	}
	const amount = form.elements.namedItem('payerAmount');
	if (amount instanceof HTMLInputElement && submission.payerAmount) amount.value = submission.payerAmount;
}

export function parseSitePaymentStatus(value: unknown): Record<string, unknown> | null {
	if (!isPlainObject(value)) return null;
	let candidate: unknown = value;
	if (Object.hasOwn(value, 'success')) {
		if (value.success !== true || !isPlainObject(value.data) || value.data.ok !== true || !Object.hasOwn(value.data, 'value')) return null;
		candidate = value.data.value;
	} else if (Object.hasOwn(value, 'ok')) {
		if (value.ok !== true || !Object.hasOwn(value, 'value')) return null;
		candidate = value.value;
	}
	if (!isPlainObject(candidate) || candidate.schemaVersion !== '1.0' || !isPaymentIntentId(candidate.intentId) ||
		(candidate.attemptId !== undefined && !isPaymentAttemptId(candidate.attemptId)) || typeof candidate.state !== 'string' ||
		!['created', 'initializing', 'requires_action', 'pending', 'unknown', 'verified_paid', 'verified_failed', 'verified_canceled', 'review_required'].includes(candidate.state) ||
		(candidate.nextAction !== undefined && (!isSafeNextAction(candidate.nextAction) || candidate.nextAction.id !== candidate.attemptId))) return null;
	return candidate;
}

/** Only a server-returned created attempt may be sent to the fixed site action endpoint. */
export function buildCreatedPaymentAction(value: unknown): { schemaVersion: '1.0'; intentId: string; attemptId: string; actionId: string } | null {
	const result = parseSitePaymentStatus(value);
	if (!result || result.state !== 'created' || !isPaymentIntentId(result.intentId) || !isPaymentAttemptId(result.attemptId)) return null;
	return { schemaVersion: '1.0', intentId: result.intentId, attemptId: result.attemptId, actionId: result.attemptId };
}

function isSafeNextAction(value: unknown): value is { readonly id: string; readonly kind: 'redirect'; readonly destination: string } {
	return isPlainObject(value) && Object.keys(value).sort().join(',') === 'destination,id,kind' &&
		isPaymentAttemptId(value.id) && value.kind === 'redirect' && safeCheckoutDestination(value.destination) !== null;
}

function sameOriginEndpoint(value: string | undefined): string | null {
	if (!value) return null;
	try {
		const url = new URL(value, globalThis.location.origin);
		return url.origin === globalThis.location.origin && !url.username && !url.password ? url.href : null;
	} catch {
		return null;
	}
}

function getSessionStorage(): Storage | null {
	try { return globalThis.sessionStorage; } catch { return null; }
}

function showStaticError(form: HTMLFormElement, message: string): void {
	const output = form.parentElement?.querySelector<HTMLElement>('#payment-status') ?? null;
	setStatus(output, message);
	disablePaymentForm(form, message);
}

function showFormError(form: HTMLFormElement, target: HTMLElement | null, message: string): void {
	if (target) { target.textContent = message; target.hidden = false; target.focus(); }
	else setStatus(form.parentElement?.querySelector<HTMLElement>('#payment-status') ?? null, message);
}

function focusFirstInvalid(form: HTMLFormElement): void {
	const invalid = form.querySelector<HTMLElement>(':invalid');
	invalid?.focus();
}

function setStatus(target: HTMLElement | null, message: string): void {
	if (target) target.textContent = message;
}

function setRecoveryVisible(target: HTMLElement | null, visible: boolean): void {
	if (target) target.hidden = !visible;
}

function disablePaymentForm(form: HTMLFormElement, message: string): void {
	setPaymentFormLocked(form, true);
	const status = form.parentElement?.querySelector<HTMLElement>('#payment-status');
	if (status) status.textContent = message;
}

function setPaymentFormLocked(form: HTMLFormElement, locked: boolean): void {
	for (const control of Array.from(form.elements)) {
		if (control instanceof HTMLInputElement || control instanceof HTMLTextAreaElement || control instanceof HTMLSelectElement || control instanceof HTMLButtonElement) {
			control.disabled = locked;
		}
	}
	if (locked) form.setAttribute('aria-disabled', 'true');
	else form.removeAttribute('aria-disabled');
}

function isValidSubmission(value: unknown, formId: string, formRevision: string): value is BrowserPaymentSubmission {
	if (!isPlainObject(value) || value.schemaVersion !== '1.0' || value.formId !== formId ||
		value.formRevision !== formRevision || !isRequestKey(value.requestKey) || !isPlainObject(value.fields) ||
		Object.keys(value.fields).length > 20) return false;
	for (const item of Object.values(value.fields)) {
		if (!(typeof item === 'string' && item.length <= 2_000 || typeof item === 'boolean')) return false;
	}
	return value.payerAmount === undefined || typeof value.payerAmount === 'string' && /^\d+(?:\.\d{1,2})?$/u.test(value.payerAmount);
}

function isPaymentReference(value: unknown): value is { readonly intentId: string; readonly attemptId?: string } {
	return isPlainObject(value) && isPaymentIntentId(value.intentId) &&
		(value.attemptId === undefined || isPaymentAttemptId(value.attemptId));
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
	const prototype = Object.getPrototypeOf(value);
	return prototype === Object.prototype || prototype === null;
}

function isIdentifier(value: unknown): value is string {
	return typeof value === 'string' && /^[A-Za-z0-9_-]{1,255}$/u.test(value);
}

function isPaymentIntentId(value: unknown): value is string {
	return typeof value === 'string' && /^psk:v1:intents:[a-f0-9]{64}$/u.test(value);
}

function isPaymentAttemptId(value: unknown): value is string {
	return typeof value === 'string' && /^psk:v1:attempts:[a-f0-9]{64}$/u.test(value);
}

function isRequestKey(value: unknown): value is string {
	return typeof value === 'string' && /^[A-Fa-f0-9-]{36}$/u.test(value);
}

function requestKeyStorageKey(formId: string, revision: string): string {
	return `emdash-paystack:request:${encodeURIComponent(formId)}:${encodeURIComponent(revision)}`;
}

function recoveryStorageKey(formId: string, revision: string): string {
	return `emdash-paystack:recovery:${encodeURIComponent(formId)}:${encodeURIComponent(revision)}`;
}

function toMinorUnits(value: string): bigint | null {
	if (typeof value !== 'string' || value.length > 32 || !/^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,2})?$/u.test(value)) return null;
	const [whole, fraction = ''] = value.split('.');
	try { return BigInt(whole!) * 100n + BigInt(fraction.padEnd(2, '0')); } catch { return null; }
}
