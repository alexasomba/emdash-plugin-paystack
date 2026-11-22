# Paystack for EmDash and DashCommerce Core

Sandboxed, NGN hosted-card checkout for DashCommerce Core. The EmDash plugin initializes Paystack transactions, verifies payments, and retains results until Core acknowledges them. A server-side companion connects Core checkout and its order recovery workflow to the sandboxed plugin.

## Installation

1. Install Paystack Payments from the EmDash registry on a site with a sandbox runner and encrypted plugin settings.
2. Install the matching Core recovery patch and the Paystack server-side companion. See the [DashCommerce guide](https://github.com/alexasomba/emdash-plugin-paystack/blob/main/integrations/dashcommerce/README.md).
3. Configure Paystack in test mode and verify one checkout with your site's result poller before enabling live admissions.

This release requires the patched DashCommerce Core build documented in the guide. Standalone payment forms, customer directory, advanced reports, refunds, subscriptions, and starting a second charge through the retry API are deferred. Scheduler reconciliation and exact-event recovery continue to work for existing payment records.
