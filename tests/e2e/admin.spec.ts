import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';

const siteOrigin = process.env.PAYSTACK_E2E_BASE_URL ?? 'http://127.0.0.1:4329';
const adminBase = new URL('/_emdash/admin/plugins/paystack-payments/', siteOrigin);

const screens = [
	{ path: 'setup', heading: 'Paystack setup' },
	{ path: 'recovery', heading: 'Recovery' },
] as const;

const forbiddenRenderedData = [
	/sk_(?:test|live)_[a-z0-9]{8,}/iu,
	/pk_(?:test|live)_[a-z0-9]{8,}/iu,
	/payer@example\.test/iu,
	/(?:cus|txn|ref)_[a-z0-9]{12,}/iu,
];

test.setTimeout(120_000);

test.beforeEach(async ({ page }) => {
	const bypass = new URL('/_emdash/api/setup/dev-bypass', siteOrigin);
	bypass.searchParams.set('redirect', '/_emdash/admin');
	await page.goto(bypass.toString());
	await expect(page).toHaveURL(/\/_emdash\/admin\/?$/u);
	const welcome = page.getByRole('button', { name: 'Get Started' });
	if (await welcome.isVisible().catch(() => false)) await welcome.click();
	await page.setViewportSize({ width: 1280, height: 900 });
});

test('renders the Paystack admin screens with named, keyboard-reachable controls and no private payment data', async ({ page }) => {
	const providerRequests: string[] = [];
	page.on('request', (request) => {
		if (new URL(request.url()).hostname === 'api.paystack.co') providerRequests.push(request.url());
	});

	for (const screen of screens) {
		await page.goto(new URL(screen.path, adminBase).toString());
		const main = page.getByRole('main');
		await expect(main.getByRole('heading', { name: screen.heading, exact: true })).toBeVisible();

		const unnamedControls = await main.evaluate((root) => {
			const controls = Array.from(root.querySelectorAll<HTMLElement>(
				'a[href], button, input:not([type="hidden"]), select, textarea, [role="combobox"]',
			));
			return controls
				.filter((element) => {
					const rect = element.getBoundingClientRect();
					const style = getComputedStyle(element);
					if (rect.width === 0 || rect.height === 0 || style.visibility === 'hidden' || element.closest('[aria-hidden="true"]')) return false;
					const labelledBy = element.getAttribute('aria-labelledby')
						?.split(/\s+/u)
						.map((id) => document.getElementById(id)?.textContent ?? '')
						.join(' ')
						.trim();
					const labels = 'labels' in element
						? Array.from((element as HTMLInputElement).labels ?? []).map((label) => label.textContent ?? '').join(' ').trim()
						: '';
					const accessibleName = element.getAttribute('aria-label') || labelledBy || labels || element.getAttribute('title') || element.textContent?.trim();
					return !accessibleName;
				})
				.map((element) => `${element.tagName.toLowerCase()} ${element.outerHTML.slice(0, 160)}`);
		});
		expect(unnamedControls, `${screen.path} has unnamed visible controls`).toEqual([]);

		const privateData = await main.evaluate((root) => `${root.textContent}\n${root.outerHTML}`);
		for (const pattern of forbiddenRenderedData) expect(privateData).not.toMatch(pattern);

		const controls = await main.evaluate((root) => {
			const candidates = Array.from(root.querySelectorAll<HTMLElement>(
				'a[href], button, input:not([type="hidden"]), select, textarea, [role="combobox"]',
			));
			return candidates
				.filter((element) => {
					const rect = element.getBoundingClientRect();
					const style = getComputedStyle(element);
					return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && !element.closest('[aria-hidden="true"]') && element.tabIndex >= 0;
				})
				.map((element) => {
					const labelledBy = element.getAttribute('aria-labelledby')
						?.split(/\s+/u)
						.map((id) => document.getElementById(id)?.textContent ?? '')
						.join(' ')
						.trim();
					const labels = 'labels' in element
						? Array.from((element as HTMLInputElement).labels ?? []).map((label) => label.textContent ?? '').join(' ').trim()
						: '';
					const name = (element.getAttribute('aria-label') || labelledBy || labels || element.getAttribute('title') || element.textContent || '').replace(/\s+/gu, ' ').trim();
					const rect = element.getBoundingClientRect();
					return {
						name,
						tag: element.tagName.toLowerCase(),
						width: rect.width,
						height: rect.height,
						centerX: rect.x + rect.width / 2,
						centerY: rect.y + rect.height / 2,
					};
				});
		});
		const undersizedTargets = controls.filter((control) => control.width < 24 || control.height < 24);
		const below44Targets = controls.filter((control) => control.width < 44 || control.height < 44);
		const unspacedUndersizedTargets = undersizedTargets.filter((target) => {
			const nearestTargetCenter = Math.min(...controls
				.filter((candidate) => candidate !== target)
				.map((candidate) => Math.hypot(candidate.centerX - target.centerX, candidate.centerY - target.centerY)));
			return nearestTargetCenter < 24;
		});
		expect(unspacedUndersizedTargets, `${screen.path} undersized targets have the WCAG spacing exception`).toEqual([]);
		console.info('Paystack admin target-size audit', JSON.stringify({
			screen: screen.path,
			controls: controls.length,
			below24px: undersizedTargets.map((target) => ({
				name: target.name,
				width: target.width,
				height: target.height,
				nearestTargetCenterDistance: Math.min(...controls
					.filter((candidate) => candidate !== target)
					.map((candidate) => Math.hypot(candidate.centerX - target.centerX, candidate.centerY - target.centerY))),
			})),
			below44px: below44Targets.map(({ name, width, height }) => ({ name, width, height })),
		}));

		const expectedNames = Array.from(new Set(controls.map((control) => control.name).filter(Boolean)));
		const reachedNames = new Set<string>();
		let visibleKeyboardFocus = false;
		await page.evaluate(() => {
			if (document.activeElement instanceof HTMLElement) document.activeElement.blur();
		});
		for (let step = 0; step < 140 && expectedNames.some((name) => !reachedNames.has(name)); step += 1) {
			await page.keyboard.press('Tab');
			const focused = await page.evaluate(() => {
				const element = document.activeElement;
				if (!(element instanceof HTMLElement)) return null;
				const main = document.querySelector('main');
				const labelledBy = element.getAttribute('aria-labelledby')
					?.split(/\s+/u)
					.map((id) => document.getElementById(id)?.textContent ?? '')
					.join(' ')
					.trim();
				const labels = 'labels' in element
					? Array.from((element as HTMLInputElement).labels ?? []).map((label) => label.textContent ?? '').join(' ').trim()
					: '';
				return {
					inMain: Boolean(main?.contains(element)),
					name: (element.getAttribute('aria-label') || labelledBy || labels || element.getAttribute('title') || element.textContent || '').replace(/\s+/gu, ' ').trim(),
					focusVisible: element.matches(':focus-visible'),
					outline: getComputedStyle(element).outlineStyle,
					outlineWidth: getComputedStyle(element).outlineWidth,
					boxShadow: getComputedStyle(element).boxShadow,
				};
			});
			if (focused?.inMain) {
				if (focused.name) reachedNames.add(focused.name);
				visibleKeyboardFocus ||= focused.focusVisible && (
					(focused.outline !== 'none' && focused.outlineWidth !== '0px') || focused.boxShadow !== 'none'
				);
			}
		}
		expect(reachedNames, `${screen.path} controls are reachable by Tab`).toEqual(new Set(expectedNames));
		if (expectedNames.length > 0) expect(visibleKeyboardFocus, `${screen.path} exposes a visible keyboard focus indicator`).toBe(true);

		const audit = await new AxeBuilder({ page })
			.include('main')
			.withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
			.analyze();
		const violations = audit.violations.map((violation) => ({
			id: violation.id,
			impact: violation.impact,
			help: violation.help,
			targets: violation.nodes.map((node) => node.target),
		}));
		expect(violations, `${screen.path} WCAG 2.2 AA violations`).toEqual([]);
	}

	await page.goto(new URL('setup', adminBase).toString());
	await expect(page.getByRole('textbox', { name: 'API secret key' })).toHaveValue('');
	expect(providerRequests).toEqual([]);
});

test('keeps the admin content usable at a narrow viewport', async ({ page }) => {
	await page.setViewportSize({ width: 390, height: 844 });
	await page.goto(new URL('recovery', adminBase).toString());
	await expect(page.getByRole('heading', { name: 'Recovery', exact: true })).toBeVisible();
	const overflow = await page.evaluate(() => ({
		viewport: document.documentElement.clientWidth,
		page: document.documentElement.scrollWidth,
		main: document.querySelector('main')?.scrollWidth ?? 0,
		mainClient: document.querySelector('main')?.clientWidth ?? 0,
	}));
	expect(overflow.page, 'the admin document should not scroll horizontally').toBeLessThanOrEqual(overflow.viewport);
	expect(overflow.main, 'plugin content should fit its EmDash admin column').toBeLessThanOrEqual(overflow.mainClient);
});
