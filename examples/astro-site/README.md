# Standalone EmDash site integration

The registry-installed Paystack plugin remains sandboxed and does not depend on DashCommerce. The site-facing code is a separate, trusted companion: a registry installation does not install server modules or site pages automatically. The npm package exports `emdash-plugin-paystack/site` for server-side helpers and `emdash-plugin-paystack/payment-form` for the Astro component. Neither export is a replacement for installing and configuring the sandboxed plugin. The npm package has not yet been released.

Build the package with `pnpm run build`. Import the site helpers only in trusted server code. Configure the actual installed plugin ID, the site-scoped attestation key and a separate identity HMAC key; use durable site-owned storage, a persistent rate limiter, same-origin and CSRF checks, and a session or guest capability. The `resolveSubmitContext` and `resolveOwnedContext` callbacks must derive the subject, merchant, immutable form revision, callback URL and any trusted order amount from site-owned state. Never take those claims from browser input.

Expose same-origin POST endpoints backed by the adapter's `submit`, `action` and `status` methods. Pass their URLs and a valid site CSRF token to the component:

```astro
---
import PaymentForm from 'emdash-plugin-paystack/payment-form';
// Obtain a published form projection through the configured EmDash site boundary.
---
<PaymentForm projection={projection} submitEndpoint="/api/payments/submit"
  actionEndpoint="/api/payments/action" statusEndpoint="/api/payments/status" csrfToken={csrfToken} />
```

A created intent is sent to the action endpoint using its existing attempt ID. Uncertain outcomes stay locked to the same intent and are checked using status after reload. A verified result can be consumed with `createResultClient` and `consumeVerifiedResult`; persist application fulfillment and its idempotency record atomically before acknowledging it. Polling requires a durable site job, scoped consumer identity and quota. Configure and test the plugin's webhook and scheduled reconciliation independently.

This is integration guidance, not a turnkey installation or a release claim. Complete the site's auth, storage, secret provisioning, trusted resolvers, job scheduling and return page, then validate with Paystack test mode and a real target host before accepting payments.
