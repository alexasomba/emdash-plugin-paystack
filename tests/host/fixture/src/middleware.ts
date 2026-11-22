import {
  createPaystackSiteAdapter,
  createPersistentPaymentStore,
  createPersistentRateLimiter,
  type PaystackSiteAdapter,
  type PaystackSiteAdapterOptions,
  type PersistentSqlDatabase,
} from '../../../../examples/astro-site/index.js';

type FixtureLocals = {
  paymentFixture?: {
    db: PersistentSqlDatabase;
    options: Omit<PaystackSiteAdapterOptions, 'store' | 'limiter'>;
  };
  paystackSiteAdapter?: PaystackSiteAdapter;
};

/** Install after the local site's session, environment and D1 bindings have been resolved. */
export async function onRequest(context: { request: Request; locals: FixtureLocals }, next: () => Promise<Response>) {
  const { pathname } = new URL(context.request.url);
  if (context.request.method === 'POST' && ['/submit', '/action', '/status'].includes(pathname)) {
    const fixture = context.locals.paymentFixture;
    if (fixture) {
      const store = createPersistentPaymentStore(fixture.db);
      context.locals.paystackSiteAdapter = createPaystackSiteAdapter({
        ...fixture.options,
        store,
        limiter: createPersistentRateLimiter(store),
      });
    }
  }
  return next();
}
