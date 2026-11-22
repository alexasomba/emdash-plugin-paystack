import { describe, expect, it } from 'vite-plus/test';
import type { ModelRecord, VersionedCollection } from '../../src/storage/schema.js';
import type { SettingsPort, VersionedSetting } from '../../src/domain/configuration.js';
import type { AdmittedPaymentSnapshot } from '../../src/storage/admission.js';
import { createDataEncryptionKey, encodeBase64Url, encryptValue } from '../../src/security/encryption.js';
import { createPaystackCheckout, type PaystackCreateDependencies } from '../../src/provider/paystack.js';
import { approvedExamples } from '../support/spec-fixtures.js';

const PLUGIN_ID = 'emdash-plugin-paystack';
const SITE_ID = 'site_race';
const PROFILE = 'merchant_profile_race';
const INTENT_ID = `psk:v1:intents:${'d'.repeat(64)}`;
const ATTEMPT_ID = `psk:v1:attempts:${'e'.repeat(64)}`;
const NOW = Date.parse('2026-10-18T09:00:00.000Z');
const FIELD_KEY = new Uint8Array(32).fill(23);

type CasFault = 'conflict' | 'throw-after-apply';

class DurableStore<T> implements VersionedCollection<T> {
  private records = new Map<string, { value: T; revision: string }>();
  private nextFault: CasFault | null = null;
  private revision = 1;

  seed(id: string, value: T): void {
    this.records.set(id, { value: structuredClone(value), revision: String(this.revision++) });
  }

  faultNextCas(fault: CasFault): void {
    this.nextFault = fault;
  }

  restart(): DurableStore<T> {
    const restarted = new DurableStore<T>();
    restarted.records = this.records;
    restarted.revision = this.revision;
    return restarted;
  }

  async getVersioned(id: string): Promise<{ value: T; revision: string } | null> {
    const found = this.records.get(id);
    return found ? structuredClone(found) : null;
  }

  async compareAndSet(id: string, expectedRevision: string | null, data: T): Promise<{ applied: true; revision: string } | { applied: false }> {
    const fault = this.nextFault;
    this.nextFault = null;
    const current = this.records.get(id);
    if (fault === 'conflict' || (current?.revision ?? null) !== expectedRevision) return { applied: false };
    const revision = String(this.revision++);
    this.records.set(id, { value: structuredClone(data), revision });
    if (fault === 'throw-after-apply') throw new Error('simulated lost CAS response after durable commit');
    return { applied: true, revision };
  }

  async compareAndDelete(id: string, expectedRevision: string): Promise<{ applied: boolean }> {
    const current = this.records.get(id);
    if (!current || current.revision !== expectedRevision) return { applied: false };
    return { applied: this.records.delete(id) };
  }

  async query(): Promise<{ items: Array<{ id: string; data: T }>; hasMore: boolean }> {
    return { items: [], hasMore: false };
  }

  read(id: string): T | null {
    const found = this.records.get(id);
    return found ? structuredClone(found.value) : null;
  }
}

class MemorySettings implements SettingsPort {
  readonly revision = 'settings-r1';
  constructor(readonly value: string) {}

  async getVersioned<T>(key: string): Promise<VersionedSetting<T> | null> {
    return key === 'paymentConfiguration' ? { value: this.value as T, revision: this.revision } : null;
  }

  async compareAndSet(): Promise<{ applied: false }> {
    return { applied: false };
  }
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

async function makeFixture() {
  const configuration = {
    schemaVersion: 1,
    paused: false,
    activeProfile: PROFILE,
    profiles: {
      [PROFILE]: {
        profileId: PROFILE,
        activeCredentialVersion: 1,
        credentialVersions: [{ version: 1, environment: 'test', secretKey: 'sk_test_runtime_fixture' }],
      },
    },
    integrationKeys: [],
    fieldEncryptionKeyRing: { activeKeyId: 'field-v1', keys: [{ keyId: 'field-v1', material: encodeBase64Url(FIELD_KEY) }] },
    identityHmacKeyRing: { activeKeyId: 'identity-v1', keys: [{ keyId: 'identity-v1', material: encodeBase64Url(new Uint8Array(32).fill(24)) }] },
  };
  const settings = new MemorySettings(JSON.stringify(configuration));
  const intents = new DurableStore<ModelRecord>();
  const budgets = new DurableStore<ModelRecord>();
  const form = approvedExamples.fixedForm;
  const snapshot: AdmittedPaymentSnapshot = {
    schemaVersion: '1.0', siteId: SITE_ID,
    subject: { kind: 'member', id: 'race_member' },
    businessReference: 'race_order', merchantProfile: PROFILE, environment: 'test', credentialVersion: 1,
    form, amount: { currency: 'NGN', value: '5000.00', minorUnits: 500_000 },
    fields: { payer_email: 'payer@example.test' }, metadata: {},
  };
  const envelope = await encryptValue(snapshot, createDataEncryptionKey('field-v1', FIELD_KEY), {
    pluginId: PLUGIN_ID, collection: 'intents', recordId: INTENT_ID, schemaVersion: 1, purpose: 'custom_fields',
  });
  const at = new Date(NOW).toISOString();
  intents.seed(INTENT_ID, {
    modelVersion: 1, siteId: SITE_ID, merchantId: PROFILE, merchantProfile: PROFILE,
    environment: 'test', credentialVersion: 1, formId: form.id, formRevision: form.revision,
    identityHmac: INTENT_ID, fingerprintHmac: 'f'.repeat(64), state: 'created', deliveryState: 'not_eligible',
    currentAttemptId: ATTEMPT_ID,
    attempts: [{
      modelVersion: 1, id: ATTEMPT_ID, ordinal: 1, predecessorId: null, state: 'created',
      providerState: 'not_started', credentialVersion: 1, createTransmissionStarted: false,
      providerReference: null, providerResourceId: null, createdAt: at, updatedAt: at, nextRunAt: NOW,
    }],
    protectedSnapshot: envelope, leaseEpoch: 0, nextRunAt: NOW, createdAt: at, updatedAt: at,
  });
  const input = {
    siteId: SITE_ID, intentId: INTENT_ID, attemptId: ATTEMPT_ID,
    siteOrigin: 'https://shop.example', callbackUrl: 'https://shop.example/payments/return',
  };
  return { settings, intents, budgets, input };
}

function createDependencies(
  fixture: Awaited<ReturnType<typeof makeFixture>>,
  fetch: PaystackCreateDependencies['fetch'],
): PaystackCreateDependencies {
  let randomCall = 0;
  return {
    pluginId: PLUGIN_ID,
    settings: fixture.settings,
    intents: fixture.intents,
    budgets: fixture.budgets,
    fetch,
    now: () => NOW,
    randomBytes: (length) => new Uint8Array(length).fill(++randomCall),
  };
}

function validProviderResponse(reference: string): Response {
  return new Response(JSON.stringify({
    status: true,
    data: { reference, authorization_url: 'https://checkout.paystack.com/session_1' },
  }), { status: 200, headers: { 'content-type': 'application/json' } });
}

describe('T035 intent and provider crash/replay boundaries', () => {
  it('admits one concurrent create, adopts an accepted provider result after a lost local-write response, and replays after restart', async () => {
    const fixture = await makeFixture();
    const response = deferred<Response>();
    const entered = deferred<{ reference: string }>();
    let transmissions = 0;
    const deps = createDependencies(fixture, async (_url, init) => {
      transmissions += 1;
      const payload = JSON.parse(String(init?.body)) as { reference: string };
      entered.resolve(payload);
      return response.promise;
    });

    const firstPromise = createPaystackCheckout(fixture.input, deps);
    const sent = await entered.promise;
    const concurrent = await createPaystackCheckout(fixture.input, deps);
    expect(concurrent.kind).toBe('pending');
    expect(transmissions).toBe(1);

    // Provider accepted, but the sandbox lost the CAS response after the outcome write committed.
    fixture.intents.faultNextCas('throw-after-apply');
    response.resolve(validProviderResponse(sent.reference));
    const first = await firstPromise;
    expect(first).toMatchObject({ kind: 'next_action', nextAction: { id: ATTEMPT_ID, kind: 'redirect' } });
    expect(fixture.intents.read(INTENT_ID)).toMatchObject({
      state: 'requires_action',
      attempts: [{ createTransmissionStarted: true, providerState: 'initialized' }],
    });

    const restarted = await createPaystackCheckout(fixture.input, {
      ...deps, intents: fixture.intents.restart(), budgets: fixture.budgets.restart(),
    });
    expect(restarted).toMatchObject({ kind: 'next_action', attemptId: ATTEMPT_ID });
    expect(transmissions).toBe(1);
  });

  it('keeps the irreversible marker after provider acceptance when the local outcome CAS conflicts', async () => {
    const fixture = await makeFixture();
    const response = deferred<Response>();
    const entered = deferred<{ reference: string }>();
    let transmissions = 0;
    const deps = createDependencies(fixture, async (_url, init) => {
      transmissions += 1;
      const payload = JSON.parse(String(init?.body)) as { reference: string };
      entered.resolve(payload);
      return response.promise;
    });
    const firstPromise = createPaystackCheckout(fixture.input, deps);
    const sent = await entered.promise;
    fixture.intents.faultNextCas('conflict');
    response.resolve(validProviderResponse(sent.reference));

    expect(await firstPromise).toMatchObject({ kind: 'pending' });
    expect(fixture.intents.read(INTENT_ID)).toMatchObject({
      state: 'initializing',
      attempts: [{ createTransmissionStarted: true, providerState: 'create_started' }],
    });
    const restarted = await createPaystackCheckout(fixture.input, {
      ...deps, intents: fixture.intents.restart(), budgets: fixture.budgets.restart(),
    });
    expect(restarted).toMatchObject({ kind: 'pending', attemptId: ATTEMPT_ID });
    expect(transmissions).toBe(1);
  });

  it('rejects an off-origin callback before making any provider transmission', async () => {
    const fixture = await makeFixture();
    let transmissions = 0;
    const deps = createDependencies(fixture, async () => {
      transmissions += 1;
      return validProviderResponse('unused');
    });
    const result = await createPaystackCheckout({
      ...fixture.input, callbackUrl: 'https://attacker.example/payments/return',
    }, deps);
    expect(result).toEqual({ kind: 'invalid' });
    expect(transmissions).toBe(0);
    expect(fixture.intents.read(INTENT_ID)).toMatchObject({ state: 'created' });
  });
});
