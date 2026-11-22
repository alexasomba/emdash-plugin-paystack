/** Minimal Cloudflare D1-compatible surface used by the reference site adapter. */
export interface PersistentSqlStatement {
	bind(...values: readonly unknown[]): PersistentSqlStatement;
	first<T = unknown>(): Promise<T | null>;
	run(): Promise<{ readonly success?: boolean }>;
}

export interface PersistentSqlDatabase {
	prepare(query: string): PersistentSqlStatement;
}

export interface PersistentPaymentStore {
	readonly durable: true;
	ensureReady(): Promise<void>;
	consumeWindow(counterKey: string, windowStartMs: number): Promise<number>;
	bindIdentityKeyFingerprint(fingerprint: string): Promise<boolean>;
	getOrCreateCohort(identityDigest: string, bucket: number): Promise<number>;
}

/**
 * Creates the site-owned durable state required by the example adapter. D1's
 * single-statement upserts make each rate-window increment atomic across
 * isolates and survive process restarts. The adapter fails closed on DB errors.
 */
export function createPersistentPaymentStore(database: PersistentSqlDatabase): PersistentPaymentStore {
	let ready: Promise<void> | undefined;
	const ensureReady = (): Promise<void> => {
		ready ??= initialize(database).catch((error: unknown) => {
			ready = undefined;
			throw error;
		});
		return ready;
	};

	return Object.freeze({
		durable: true as const,
		ensureReady,
		async consumeWindow(counterKey: string, windowStartMs: number): Promise<number> {
			await ensureReady();
			const row = await database.prepare(`
				INSERT INTO emdash_paystack_rate_windows (counter_key, window_start_ms, count)
				VALUES (?, ?, 1)
				ON CONFLICT(counter_key) DO UPDATE SET
					count = CASE
						WHEN emdash_paystack_rate_windows.window_start_ms < excluded.window_start_ms THEN 1
						ELSE emdash_paystack_rate_windows.count + 1
					END,
					window_start_ms = MAX(
						emdash_paystack_rate_windows.window_start_ms,
						excluded.window_start_ms
					)
				RETURNING count
			`).bind(counterKey, windowStartMs).first<{ count: number }>();
			if (!row || !Number.isSafeInteger(row.count) || row.count < 1) {
				throw new Error('Persistent rate counter did not return a valid count');
			}
			return row.count;
		},
		async bindIdentityKeyFingerprint(fingerprint: string): Promise<boolean> {
			await ensureReady();
			const inserted = await database.prepare(`
				INSERT INTO emdash_paystack_identity_key_binding (binding_id, fingerprint)
				VALUES ('installation-identity-hmac-v1', ?)
				ON CONFLICT(binding_id) DO NOTHING
			`).bind(fingerprint).run();
			if (inserted.success === false) throw new Error('Could not bind installation identity key');
			const row = await database.prepare(`
				SELECT fingerprint
				FROM emdash_paystack_identity_key_binding
				WHERE binding_id = 'installation-identity-hmac-v1'
			`).first<{ fingerprint: string }>();
			return row?.fingerprint === fingerprint;
		},
		async getOrCreateCohort(identityDigest: string, bucket: number): Promise<number> {
			await ensureReady();
			const inserted = await database.prepare(`
				INSERT INTO emdash_paystack_rollout_cohorts (identity_digest, bucket, assigned_at_ms)
				VALUES (?, ?, ?)
				ON CONFLICT(identity_digest) DO NOTHING
			`).bind(identityDigest, bucket, Date.now()).run();
			if (inserted.success === false) throw new Error('Could not persist rollout assignment');
			const row = await database.prepare(`
				SELECT bucket
				FROM emdash_paystack_rollout_cohorts
				WHERE identity_digest = ?
			`).bind(identityDigest).first<{ bucket: number }>();
			if (!row || !Number.isSafeInteger(row.bucket) || row.bucket < 0 || row.bucket > 9_999) {
				throw new Error('Persistent rollout assignment is invalid');
			}
			return row.bucket;
		},
	});
}

async function initialize(database: PersistentSqlDatabase): Promise<void> {
	const statements = [
		`CREATE TABLE IF NOT EXISTS emdash_paystack_rate_windows (
			counter_key TEXT PRIMARY KEY NOT NULL,
			window_start_ms INTEGER NOT NULL,
			count INTEGER NOT NULL CHECK (count >= 1)
		)`,
		`CREATE TABLE IF NOT EXISTS emdash_paystack_identity_key_binding (
			binding_id TEXT PRIMARY KEY NOT NULL,
			fingerprint TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS emdash_paystack_rollout_cohorts (
			identity_digest TEXT PRIMARY KEY NOT NULL,
			bucket INTEGER NOT NULL CHECK (bucket >= 0 AND bucket <= 9999),
			assigned_at_ms INTEGER NOT NULL
		)`,
	];
	for (const statement of statements) {
		const result = await database.prepare(statement).run();
		if (result.success === false) throw new Error('Could not initialize payment site persistence');
	}
}
