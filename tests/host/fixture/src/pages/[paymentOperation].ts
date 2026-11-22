import type { PaystackSiteAdapter } from '../../../../../examples/astro-site/server-adapter/index.js';

type SiteContext = {
  request: Request;
  params: { paymentOperation?: string };
  locals: { paystackSiteAdapter?: PaystackSiteAdapter };
};

export async function POST({ request, params, locals }: SiteContext): Promise<Response> {
  const operation = params.paymentOperation;
  if (operation !== 'submit' && operation !== 'action' && operation !== 'status') {
    return new Response(null, { status: 404 });
  }

  const adapter = locals.paystackSiteAdapter;
  if (!adapter) {
    return Response.json({ code: 'provider_unavailable' }, { status: 503 });
  }

  return adapter[operation](request);
}
