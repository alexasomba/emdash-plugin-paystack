import { describe, expect, it } from 'vite-plus/test';
import { approvedExamples } from '../support/spec-fixtures.js';
import { maskEmail, projectAdminPayment, projectAdminPaymentDetail } from '../../src/domain/admin-projection.js';
import { handleInspection, type InspectionDependencies } from '../../src/routes/inspection.js';
import { createIndexHmacKey } from '../../src/security/encryption.js';
import { signInspectionCursor, verifyInspectionCursor } from '../../src/storage/cursors.js';

describe('admin inspection projection and privacy contracts', () => {
  it('TC-ADM-001 masks valid email addresses and omits malformed or non-string input', () => {
    for (const example of approvedExamples.adminProjection.maskingCases) {
      expect(maskEmail(example.input)).toBe(example.omitField ? undefined : example.expected);
    }
    expect(maskEmail({ email: 'payer@example.test' })).toBeUndefined();
  });

  it('TC-ADM-002 projects only approved fields and suppresses nested sensitive values', () => {
    const payment = approvedExamples.adminProjection.acceptedProjections.payments;
    const privateValue = 'payer@example.test';
    const row = projectAdminPayment({ ...payment, metadata: { email: privateValue }, providerPayload: privateValue,
      signature: 'secret-signature', customFields: { note: privateValue } });
    expect(row).toEqual(payment);
    const detail = projectAdminPaymentDetail({ ...payment, email: privateValue,
      history: [{ attemptId: 'attempt_1', state: privateValue, failureCode: 'raw provider secret', payload: privateValue }] });
    expect(detail?.history).toEqual([{ attemptId: 'attempt_1', state: 'unknown', failureCode: 'unknown' }]);
    expect(JSON.stringify(detail)).not.toContain(privateValue);
    expect(JSON.stringify(detail)).not.toContain('raw provider secret');
  });

  it('TC-ADM-003 rejects unbounded or extra query fields before reading storage and binds cursors to site scope', async () => {
    let reads = 0;
    const deps = { settings: { getVersioned: async () => { reads++; return null; } } } as unknown as InspectionDependencies;
    for (const request of [{ view: 'payments', limit: 51 }, { view: 'payments', providerPayload: true }]) {
      expect(await handleInspection(request, deps)).toMatchObject({ ok: false, error: { code: 'validation_error' } });
    }
    expect(reads).toBe(0);
    const key = createIndexHmacKey('key', new Uint8Array(32).fill(4));
    const keys = { activeKeyId: key.keyId, keys: [key] };
    const scope = { siteBinding: 'site-a', view: 'payments' as const, filter: null, sort: 'createdAt:desc' as const, limit: 10 };
    const cursor = await signInspectionCursor('next-page', scope, keys, 1000);
    expect(cursor).not.toBeNull();
    expect(await verifyInspectionCursor(cursor, { ...scope, siteBinding: 'site-b' }, keys, 1001)).toBeNull();
    // Authentication, RBAC and CSRF are enforced by the host; tests/host/inspection.test.ts exercises those boundaries.
  });
});
