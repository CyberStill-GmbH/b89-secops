import { describe, expect, it } from 'vitest';
import { formatLatencySummary, formatOutboxQueueSummary } from './operations_view';

describe('operations latency copy', () => {
  it('uses readable separators and Spanish labels for handler latency', () => {
    expect(formatLatencySummary(1.4, 2.6, 3.2, 8)).toBe(
      'p50 1 ms · p95 3 ms · p99 3 ms · 8 muestras',
    );
  });

  it('falls back to p95 when p50 or p99 is unavailable', () => {
    expect(formatLatencySummary(null, 12, null, 1)).toBe(
      'p50 0 ms · p95 12 ms · p99 12 ms · 1 muestra',
    );
  });
});

describe('operations outbox lease copy', () => {
  it('shows expired lease count and age without inventing age when there are none', () => {
    expect(
      formatOutboxQueueSummary({
        pending: 2,
        processing: 3,
        oldestPendingAgeSeconds: 61,
        expiredProcessing: 2,
        oldestExpiredLeaseAgeSeconds: 9,
      }),
    ).toBe(
      '2 pendientes · 3 en curso · más antigua 1 min · 2 leases vencidos · lease más antiguo vencido hace 9 s',
    );
    expect(
      formatOutboxQueueSummary({
        pending: 0,
        processing: 1,
        oldestPendingAgeSeconds: null,
        expiredProcessing: 0,
        oldestExpiredLeaseAgeSeconds: null,
      }),
    ).toBe('0 pendientes · 1 en curso · más antigua Sin dato · 0 leases vencidos');
  });
});
