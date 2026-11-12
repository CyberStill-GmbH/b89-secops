import { describe, expect, it } from 'vitest';
import { formatLatencySummary } from './operations_view';

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
