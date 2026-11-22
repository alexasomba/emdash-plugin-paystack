# DashCommerce Core checkout and recovery

Use EmDash 1.5.0 and DashCommerce Core 0.3.5 at upstream commit `1bd6a82132008a3444d1f70413fbd1d443565a14` with [the recovery patch](core-recovery.patch). The patch enables provider-managed relay credentials, reserves one checkout draft per cart, retries recoverable result deliveries, and gives authenticated operators a revision-checked way to review repaired orders. It applies to a clean checkout of that commit. Follow [Core's upstream EmDash host patch instructions](https://github.com/emdashCommerce/dashcommerce/tree/1bd6a82132008a3444d1f70413fbd1d443565a14/packages/core/patches) for the matching Core/EmDash compatibility patch, then build and install the patched Core package.

The registry bundle runs the Paystack backend. Build and install this source package in your site's native runtime for the `emdash-plugin-paystack/dashcommerce` export. Use `vp install`, `vp run validate`, `vp run build`, and `npm pack --ignore-scripts` to produce an installable tarball. Pin both packages to the versions you tested. Core must run as its native plugin so the companion and Core use the same payment provider registry.

## Configure the sandbox

1. Confirm the site has encrypted EmDash plugin settings and a runner with scheduler support. On Cloudflare Workers, connect the Worker's scheduled event to EmDash's scheduled-task entry point. Leave payment admission paused during setup.
2. Use the plugin's authenticated `configuration` route to `read`, then `save` using that response's `revision` as `expectedRevision`. Use a Paystack **test** secret for the first setup. Supply `environment: "test"`, `merchantProfile`, `credentials: { secretKey }`, and these two entries in `integrationKeys`:

   | Purpose | Required binding |
   | --- | --- |
   | `site-payment` | `siteId`, `keyId`, and `secretBase64url` |
   | `result-consumer` | The same `siteId`, a different `keyId` and `secretBase64url`, and a `consumerId` |

   Generate two distinct 32-byte keys. Store the raw equivalents in your site's secret store for the companion. The save replaces the key list, so include the entries the site still uses. Calls require an EmDash administrator with `plugins:manage` and the EmDash mutations header `x-emdash-request: 1` for a cookie session. Send JSON over HTTPS from a trusted admin client and keep these values out of logs.
3. POST `{"action":"provision","formId":"dashcommerce_checkout"}` to the authenticated `forms` route. Keep the returned form ID and revision. The route publishes a trusted-order definition with one payer email field and preserves existing records. Core determines the amount server-side.
4. Configure Paystack's test webhook to POST to the plugin's public `provider/webhook` route. The sandbox validates the exact bytes against the Paystack API secret. Core's webhook receives the companion's separately signed relay message.

## Register the companion

Construct `createDashcommerceIntegration` once in the trusted site runtime, and call its `register` method with `registerPaymentProvider` from `@dashcommerce/core/payment-provider` in that same runtime. POST `{"paymentProvider":"paystack","checkoutMode":"hosted"}` to Core’s authenticated `admin/settings` route. The companion takes the following options:

| Option | What to provide |
| --- | --- |
| `checkout` | The installed Paystack plugin ID, site ID, site-payment key ID and raw bytes, profile, environment, provisioned form ID/revision, and exact HTTPS site origin |
| `resultClient` | The same plugin and site IDs, consumer ID, result-consumer key ID and raw bytes, and a site-owned quota check |
| `bindings` | A site-owned durable KV adapter with `getVersioned` and `compareAndSet`; bind and replay must use the same store |
| `relaySecret` | A separate randomly generated 32-byte secret encoded as lowercase hex |
| `deliver` | A trusted invocation of Core's webhook with the original body and signature, returning Core's actual HTTP response |

For `deliver`, the native EmDash runtime's trusted server API can dispatch the request without a network round trip:

```ts
import { withEmDashRuntime } from "emdash/middleware";

async function deliver(body: string, signature: string): Promise<Response> {
  return withEmDashRuntime(async (runtime) => {
    const request = new Request("https://emdash.internal/checkout/webhook", {
      method: "POST",
      headers: { "content-type": "application/json", "x-paystack-signature": signature },
      body,
    });
    const result = await runtime.handlePluginApiRoute("dashcommerce", "POST", "/checkout/webhook", request);
    const response = result.data;
    if (result.success && response && typeof response === "object" &&
        "status" in response && typeof response.status === "number" &&
        "clone" in response && typeof response.clone === "function") {
      return response as Response;
    }
    return new Response(null, { status: 503 });
  });
}
```

Run `poll` from a trusted site job. Continue at `nextCursor` within a scan, then start the next scan at its beginning. Core returns a retry response when ordered work is unresolved. The companion acknowledges a verified result only after Core confirms durable handling. Verify the site job, scheduler, test checkout, Core order, and result acknowledgement before enabling live payments.

## Recover an interrupted order

Find the order in Core and check its timeline. A replay repairs missing item rows using their original identities. If inventory effects need review, inspect the items and actual inventory, then record the review with the order recovery control. Confirmation leaves the order on hold. The next successful relay acknowledgement clears the Paystack result from the pending feed. Make fulfilment decisions separately based on the reviewed inventory and payment evidence.

The Paystack **Recovery** page can also reconcile an exact stored webhook inbox ID. It checks with Paystack before storing a paid result.
