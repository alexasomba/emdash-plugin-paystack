export type BridgeKind = 'settings' | 'storage' | 'http' | 'cron' | 'log';

export interface BridgeCall {
  readonly kind: BridgeKind;
  readonly operation: string;
  readonly ordinal: number;
}

export class RpcLedger {
  readonly calls: BridgeCall[] = [];

  record(kind: BridgeKind, operation: string): void {
    this.calls.push({ kind, operation, ordinal: this.calls.length + 1 });
  }

  count(kind?: BridgeKind): number {
    return kind ? this.calls.filter((call) => call.kind === kind).length : this.calls.length;
  }

  countOperation(operation: string): number {
    return this.calls.filter((call) => call.operation === operation).length;
  }

  snapshot(): readonly BridgeCall[] {
    return Object.freeze([...this.calls]);
  }
}

export class FakeClock {
  private currentMs: number;

  constructor(startAt = Date.parse('2026-10-18T00:00:00.000Z')) {
    this.currentMs = startAt;
  }

  now(): number {
    return this.currentMs;
  }

  iso(): string {
    return new Date(this.currentMs).toISOString();
  }

  advance(milliseconds: number): void {
    if (!Number.isFinite(milliseconds) || milliseconds < 0) {
      throw new RangeError('FakeClock.advance requires a finite non-negative duration');
    }
    this.currentMs += milliseconds;
  }
}

export interface ProviderRequest {
  readonly method: string;
  readonly url: string;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: string;
}

export interface ProviderResponse {
  readonly status: number;
  readonly headers?: Readonly<Record<string, string>>;
  readonly body: string;
}

export interface ProviderRequestObservation {
  readonly method: string;
  readonly url: string;
  readonly headerNames: readonly string[];
}

export interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
  reject(reason: unknown): void;
}

export function deferred<T>(): Deferred<T> {
  let resolvePromise!: (value: T) => void;
  let rejectPromise!: (reason: unknown) => void;
  const promise = new Promise<T>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return {
    promise,
    resolve: resolvePromise,
    reject: rejectPromise,
  };
}

export class FakeProviderNetwork {
  readonly requests: ProviderRequestObservation[] = [];
  private readonly responders: Array<(request: ProviderRequest) => Promise<ProviderResponse>> = [];

  constructor(private readonly ledger: RpcLedger) {}

  get transmissions(): number {
    return this.requests.length;
  }

  enqueue(response: ProviderResponse): void {
    this.responders.push(async () => response);
  }

  enqueueHandler(handler: (request: ProviderRequest) => Promise<ProviderResponse>): void {
    this.responders.push(handler);
  }

  enqueueDeferred(reply: Deferred<ProviderResponse>): void {
    this.enqueueHandler(() => reply.promise);
  }

  async fetch(request: ProviderRequest): Promise<ProviderResponse> {
    this.ledger.record('http', 'ctx.http.fetch');
    this.requests.push({
      method: request.method,
      url: request.url,
      headerNames: Object.freeze(Object.keys(request.headers ?? {}).sort()),
    });
    const responder = this.responders.shift();
    if (!responder) {
      return { status: 501, body: '' };
    }
    return responder(request);
  }
}

export type CasFault = 'conflict' | 'unknown-before-commit' | 'unknown-after-commit' | 'crash-after-commit';
export type CasResult =
  | { readonly kind: 'written'; readonly revision: number }
  | { readonly kind: 'conflict'; readonly revision: number | null }
  | { readonly kind: 'unknown' };

interface VersionedValue {
  readonly revision: number;
  readonly value: unknown;
}

interface CasBackend {
  readonly records: Map<string, VersionedValue>;
  nextFault?: CasFault;
}

export class InjectedCrash extends Error {
  readonly code = 'INJECTED_CRASH';

  constructor() {
    super('Injected crash after durable compare-and-set');
    this.name = 'InjectedCrash';
  }
}

export class PersistentCasStore {
  private readonly backend: CasBackend;

  constructor(
    private readonly ledger: RpcLedger,
    backend?: CasBackend,
  ) {
    this.backend = backend ?? { records: new Map() };
  }

  injectNext(fault: CasFault): void {
    this.backend.nextFault = fault;
  }

  async get<T>(key: string): Promise<{ readonly revision: number; readonly value: T } | null> {
    this.ledger.record('storage', 'storage.get');
    const record = this.backend.records.get(key);
    return record ? { revision: record.revision, value: structuredClone(record.value) as T } : null;
  }

  async compareAndSet(
    key: string,
    expectedRevision: number | null,
    value: unknown,
  ): Promise<CasResult> {
    this.ledger.record('storage', 'storage.compareAndSet');
    const existing = this.backend.records.get(key);
    const currentRevision = existing?.revision ?? null;
    const fault = this.backend.nextFault;
    delete this.backend.nextFault;

    if (fault === 'conflict' || currentRevision !== expectedRevision) {
      return { kind: 'conflict', revision: currentRevision };
    }
    if (fault === 'unknown-before-commit') {
      return { kind: 'unknown' };
    }

    const revision = (currentRevision ?? 0) + 1;
    this.backend.records.set(key, { revision, value: structuredClone(value) });
    if (fault === 'crash-after-commit') {
      throw new InjectedCrash();
    }
    if (fault === 'unknown-after-commit') {
      return { kind: 'unknown' };
    }
    return { kind: 'written', revision };
  }

  restart(): PersistentCasStore {
    return new PersistentCasStore(this.ledger, this.backend);
  }

  inspect<T>(key: string): { readonly revision: number; readonly value: T } | null {
    const record = this.backend.records.get(key);
    return record ? { revision: record.revision, value: structuredClone(record.value) as T } : null;
  }
}

export type FeatureOperation =
  | 'configuration.read'
  | 'configuration.save'
  | 'configuration.health'
  | 'form.create'
  | 'form.publish'
  | 'form.render'
  | 'payment.submit'
  | 'payment.action'
  | 'payment.status'
  | 'provider.initialize'
  | 'webhook.accept'
  | 'admin.inspect'
  | 'recovery.run'
  | 'registry.validate'
  | 'extension.validate'
  | 'results.feed'
  | 'results.ack'
  | 'lifecycle.rotate'
  | 'lifecycle.erase';

export interface UnimplementedOperation {
  readonly kind: 'unimplemented';
  readonly code: 'UNIMPLEMENTED';
  readonly operation: FeatureOperation;
}

export interface ImplementedOperation<T = unknown> {
  readonly kind: 'implemented';
  readonly value: T;
}

export type OperationResult<T = unknown> = UnimplementedOperation | ImplementedOperation<T>;
export type OperationHandler = (input: unknown) => Promise<unknown> | unknown;

export class PaymentTestDriver {
  readonly ledger = new RpcLedger();
  readonly clock: FakeClock;
  readonly network: FakeProviderNetwork;
  readonly storage: PersistentCasStore;
  private readonly handlers = new Map<FeatureOperation, OperationHandler>();

  constructor(options?: {
    readonly clock?: FakeClock;
    readonly storage?: PersistentCasStore;
    readonly handlers?: ReadonlyMap<FeatureOperation, OperationHandler>;
  }) {
    this.clock = options?.clock ?? new FakeClock();
    this.storage = options?.storage ?? new PersistentCasStore(this.ledger);
    this.network = new FakeProviderNetwork(this.ledger);
    for (const [operation, handler] of options?.handlers ?? []) {
      this.handlers.set(operation, handler);
    }
  }

  register(operation: FeatureOperation, handler: OperationHandler): void {
    this.handlers.set(operation, handler);
  }

  async invoke<T = unknown>(operation: FeatureOperation, input: unknown): Promise<OperationResult<T>> {
    const handler = this.handlers.get(operation);
    if (!handler) {
      return { kind: 'unimplemented', code: 'UNIMPLEMENTED', operation };
    }
    return { kind: 'implemented', value: (await handler(input)) as T };
  }

  rpc<T>(kind: BridgeKind, operation: string, action: () => T | Promise<T>): Promise<T> {
    this.ledger.record(kind, operation);
    return Promise.resolve(action());
  }

  restart(): PaymentTestDriver {
    return new PaymentTestDriver({
      clock: this.clock,
      storage: this.storage.restart(),
      handlers: this.handlers,
    });
  }
}
