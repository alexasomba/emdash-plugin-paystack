// Disposable host-site configuration reference. The executable boundary probe
// uses @emdash-cms/plugin-test's real EmDash runtime rather than starting Astro.
import emdash from 'emdash/astro';

export default {
  output: 'server',
  integrations: [emdash({ sandboxEnabled: true })],
};
