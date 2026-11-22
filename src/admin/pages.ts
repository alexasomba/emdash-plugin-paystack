import type { PluginContext, SandboxedRouteContext } from 'emdash/plugin';
import type { ConfigurationState, DomainResult } from '../domain/configuration.js';
import { isPlainObject } from '../storage/schema.js';
import { configurationRoute } from '../routes/admin.js';
import { reconciliationRoute } from '../routes/reconciliation.js';

type SetupStatus = {
	title: string;
	description: string;
	variant?: 'default' | 'alert' | 'error';
};

type SetupValues = {
	environment?: 'test' | 'live';
	merchantProfile?: string;
	publicKey?: string;
};

const SETUP_FORM_PREFIX = 'setup-save:';
const MAX_BLOCK_REVISION_LENGTH = 512;
const isRevision = (value: unknown): value is string =>
	typeof value === 'string' && value.length > 0 && value.length <= 255 && !/[\r\n]/u.test(value);
export async function adminPage(route: SandboxedRouteContext, ctx: PluginContext): Promise<unknown> {
	const input = isPlainObject(route.input) ? route.input : {};
	if (input.page === '/recovery') return recoveryPage(route, ctx, input);
	if (input.page === '/setup' || input.page === undefined) return setupPage(route, ctx, input);
	return page('Payment administration', [], notice('Screen unavailable', 'Choose Setup or Recovery.', 'error'));
}

async function setupPage(route: SandboxedRouteContext, ctx: PluginContext, input: Record<string, unknown>) {
	const call = (command: Record<string, unknown>) =>
		configurationRoute({ ...route, input: command }, ctx) as Promise<DomainResult<ConfigurationState>>;
	const action = input.action_id;
	const value = isPlainObject(input.value) ? input.value : {};
	const fields = isPlainObject(input.values) ? input.values : {};
	const revision = revisionFromBlockId(input.block_id);
	let command: Record<string, unknown> = { action: 'read' };
	if (input.type === 'form_submit' && action === 'save-configuration' && revision !== undefined) {
		const { environment, merchantProfile, publicKey, secretKey } = fields;
		const credentials = {
			...(typeof secretKey === 'string' && secretKey ? { secretKey } : {}),
			...(typeof publicKey === 'string' && publicKey ? { publicKey } : {}),
		};
		command = { action: 'save', environment, merchantProfile, expectedRevision: revision,
			...(Object.keys(credentials).length > 0 ? { credentials } : {}) };
	} else if (input.type === 'block_action' && action === 'set-admission') {
		command = { action: 'pause', paused: value.paused, expectedRevision: value.revision };
	} else if (input.type === 'block_action' && action === 'check-configuration') {
		command = { action: 'health' };
	}
	const result = await call(command);
	if (result.ok) return renderSetupPage(result.value,
		command.action === 'save' ? notice('Configuration saved', 'Check the provider before enabling admission.') : undefined,
		undefined, { providerChecked: command.action === 'health' });
	const uncertain = result.error.code === 'storage_unavailable' && command.action !== 'read';
	return renderSetupPage(null, notice(uncertain ? 'Save outcome unknown' : 'Configuration unavailable',
		'Reload the configuration before trying again.', 'error'), undefined, { reloadRequired: true });
}

export function renderSetupPage(state: ConfigurationState | null, status?: SetupStatus, values?: SetupValues,
	options: { reloadRequired?: boolean; providerChecked?: boolean } = {}): { blocks: unknown[] } {
	const blocks: unknown[] = [
		{ type: 'context', text: 'Admission starts paused. API secrets are write-only.' },
		{ type: 'fields', fields: [
			{ label: 'Configuration', value: state?.configured ? 'Configured' : 'Not configured' },
			{ label: 'Admission', value: state?.paused === false ? 'Enabled' : 'Paused' },
			{ label: 'Provider', value: options.providerChecked ? state?.health ?? 'Unknown' : 'Not checked' },
		] },
	];
	if (!state || options.reloadRequired) {
		if (values?.merchantProfile) blocks.push({ type: 'context', text: `Merchant profile: ${values.merchantProfile}` });
		blocks.push(actions(button('reload-configuration', 'Reload configuration')));
	} else {
		const environment = values?.environment ?? state.environment ?? 'test';
		blocks.push(form(revisionBlockId(state.revision), [
			{ type: 'select', action_id: 'environment', label: 'Environment', initial_value: environment,
				options: [{ label: 'Test', value: 'test' }, { label: 'Live', value: 'live' }] },
			text('merchantProfile', 'Merchant profile', values?.merchantProfile ?? state.merchantProfile ?? ''),
			text('publicKey', 'Public key (optional)', values?.publicKey ?? ''),
			{ type: 'secret_input', action_id: 'secretKey', label: 'API secret key', has_value: state.configured },
		], 'save-configuration', 'Save configuration'));
		blocks.push(actions(button('check-configuration', 'Check configuration'),
			...(state.configured ? [button('set-admission', state.paused ? 'Enable new payment admission' : 'Pause new payment admission',
				{ revision: state.revision, paused: !state.paused }, { title: state.paused ? 'Enable payments?' : 'Pause payments?',
					text: 'Existing payments remain available for recovery.', confirm: 'Apply', deny: 'Cancel' })] : [])));
	}
	return page('Paystack setup', blocks, status);
}

async function recoveryPage(route: SandboxedRouteContext, ctx: PluginContext, input: Record<string, unknown>) {
	let status: SetupStatus | undefined;
	if (input.type === 'form_submit' && input.action_id === 'reconcile-event' && isPlainObject(input.values)) {
		const result = await reconciliationRoute({ ...route, input: { eventId: input.values.eventId } }, ctx) as DomainResult<{ remainingUnresolved: number }>;
		status = result.ok && result.value.remainingUnresolved === 0
			? notice('Recovery processed', 'The stored event was processed.')
			: notice('Recovery needs review', 'The event could not be resolved. Check the stored payment before retrying.', 'alert');
	}
	return page('Recovery', [
		{ type: 'context', text: 'Unresolved payments are checked by scheduled reconciliation. Reconcile a stored webhook event by its inbox ID.' },
		form('recovery-event', [text('eventId', 'Webhook inbox ID', '')], 'reconcile-event', 'Reconcile event'),
	], status);
}

function notice(title: string, description: string, variant?: SetupStatus['variant']): SetupStatus {
	return { title, description, ...(variant ? { variant } : {}) };
}
function page(title: string, blocks: unknown[], status?: SetupStatus) {
	return {
		blocks: [{ type: 'header', text: title }, ...(status ? [{ type: 'banner', ...status }] : []), ...blocks],
		...(status?.variant === 'error' ? { toast: { type: 'error', message: status.title } } : {}),
	};
}
function text(action_id: string, label: string, initial_value: string) {
	return { type: 'text_input', action_id, label, initial_value };
}
function form(block_id: string, fields: unknown[], action_id: string, label: string) {
	return { type: 'form', block_id, fields, submit: { action_id, label } };
}
function button(action_id: string, label: string, value?: unknown, confirm?: unknown) {
	return { type: 'button', action_id, label, ...(value === undefined ? {} : { value }), ...(confirm ? { confirm } : {}) };
}
function actions(...elements: unknown[]) {
	return { type: 'actions', elements };
}

function revisionBlockId(revision: string | null): string {
	const encoded = revision === null ? '' : encodeURIComponent(revision);
	return `${SETUP_FORM_PREFIX}${encoded}`;
}

function revisionFromBlockId(value: unknown): string | null | undefined {
	if (typeof value !== 'string' || !value.startsWith(SETUP_FORM_PREFIX)) return undefined;
	const encoded = value.slice(SETUP_FORM_PREFIX.length);
	if (encoded.length > MAX_BLOCK_REVISION_LENGTH) return undefined;
	if (encoded === '') return null;
	try {
		const revision = decodeURIComponent(encoded);
		return isRevision(revision) ? revision : undefined;
	} catch {
		return undefined;
	}
}
