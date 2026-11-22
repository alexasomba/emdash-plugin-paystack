import { describe, expect, it } from 'vite-plus/test';
import { approvedExamples } from '../support/spec-fixtures.js';
import { validateFormDefinition, validateFormMetadata } from '../../src/domain/forms.js';

describe('versioned payment form extension contracts', () => {
  it('TC-EXT-001 accepts supported field kinds and rejects duplicate or invalid field IDs', () => {
    const fields = [
      { id: 'field_a', type: 'text', label: 'Text' },
      { id: 'field_b', type: 'email', label: 'Email' },
      { id: 'field_c', type: 'textarea', label: 'Message' },
      { id: 'field_d', type: 'select', label: 'Choice', options: ['One', 'Two'] },
      { id: 'field_e', type: 'checkbox', label: 'Agree' },
    ];
    expect(validateFormDefinition({ ...approvedExamples.fixedForm, fields }).ok).toBe(true);
    expect(validateFormDefinition({ ...approvedExamples.fixedForm, fields: [{ id: 'note', type: 'text', label: 'Amounts < 5000' }] }).ok).toBe(true);
    expect(validateFormDefinition({ ...approvedExamples.fixedForm, fields: [fields[0], fields[0]] })).toEqual({ ok: false, error: 'validation_error' });
    expect(validateFormDefinition({ ...approvedExamples.fixedForm, fields: [{ id: 'bad-id', type: 'text', label: 'Bad' }] })).toEqual({ ok: false, error: 'validation_error' });
  });

  it('TC-EXT-002 bounds metadata and rejects markup, regex rules, reserved keys and unknown field kinds', () => {
    const policy = { allowedKeys: ['site.campaign'], maxBytes: 4096 };
    expect(validateFormMetadata(policy, { 'site.campaign': 'spring' })).toEqual({ ok: true, value: { 'site.campaign': 'spring' } });
    expect(validateFormMetadata(policy, { 'site.campaign': 'x'.repeat(4097) })).toEqual({ ok: false, error: 'validation_error' });
    expect(validateFormMetadata(policy, JSON.parse('{"__proto__":"x"}'))).toEqual({ ok: false, error: 'validation_error' });
    for (const field of [
      { id: 'title', type: 'text', label: '<script>alert(1)</script>' },
      { id: 'title', type: 'text', label: '<b>title</b>' },
      { id: 'title', type: 'text', label: 'Title', pattern: '(a+)+' },
      { id: 'constructor', type: 'text', label: 'Title' },
      { id: 'title', type: 'unknown-kind', label: 'Title' },
    ]) expect(validateFormDefinition({ ...approvedExamples.fixedForm, fields: [field] })).toEqual({ ok: false, error: 'validation_error' });
  });

  it('TC-EXT-003 rejects unsupported versions and the legacy donation alias', () => {
    expect(validateFormDefinition({ ...approvedExamples.payerEnteredForm, schemaVersion: '99.0' })).toEqual({ ok: false, error: 'unsupported_schema' });
    expect(validateFormDefinition({ ...approvedExamples.payerEnteredForm, donationAmount: '20.00' })).toEqual({ ok: false, error: 'validation_error' });
  });
});
