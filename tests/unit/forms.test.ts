import { describe, expect, it } from 'vite-plus/test';
import { approvedExamples } from '../support/spec-fixtures.js';
import { expectBusinessOutcome } from '../support/behavior-assertions.js';
import { createFormTestDriver } from './forms-test-driver.js';

describe('payment form pricing and revision contracts', () => {
  it('TC-FRM-001 accepts all approved pricing modes and rejects malformed, exponent, non-finite, and out-of-range money', async () => {
    const driver = createFormTestDriver();
    for (const form of [approvedExamples.fixedForm, approvedExamples.orderForm, approvedExamples.payerEnteredForm]) {
      await expectBusinessOutcome(driver, 'form.create', { action: 'validate', definition: form }, {
        ok: true, value: { valid: true, schemaVersion: '1.0' },
      });
    }
    await expectBusinessOutcome(driver, 'form.create', {
      action: 'validate-money', values: ['1e3', 'NaN', 'Infinity', '49.99', '1000000.01', '10.001'],
    }, { ok: false, error: { code: 'validation_error' } });
  });

  it('TC-FRM-002 uses create-only null revision and non-null public definition revisions for updates and publishing', async () => {
    const driver = createFormTestDriver();
    await expectBusinessOutcome(driver, 'form.create', {
      action: 'save', expectedRevision: null, definition: approvedExamples.fixedForm,
    }, { ok: true, value: { formId: 'example_variable_payment', revision: '1', state: 'draft' } });
    await expectBusinessOutcome(driver, 'form.publish', {
      action: 'publish', formId: 'example_variable_payment', expectedRevision: '1',
    }, { ok: true, value: { formId: 'example_variable_payment', revision: '2', state: 'published' } });
  });

  it('TC-FRM-003 fences stale edits and archives before new admission while preserving old payment references', async () => {
    const driver = createFormTestDriver({ seedPublishedFixture: true });
    await expectBusinessOutcome(driver, 'form.publish', {
      action: 'save', definition: approvedExamples.fixedForm, expectedRevision: 'old-definition-rev',
    }, { ok: false, error: { code: 'stale_revision' } });
    await expectBusinessOutcome(driver, 'form.publish', {
      action: 'archive', formId: 'example_variable_payment', expectedRevision: '1',
    }, { ok: true, value: { newAdmission: false, existingIntentStatus: 'available' } });
  });
});
