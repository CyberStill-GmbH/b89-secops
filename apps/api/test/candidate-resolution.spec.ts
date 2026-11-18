import { describe, expect, it, vi } from 'vitest';
import { findEmittingCandidate } from '../src/assistant/candidate-members.js';

const id = 'rc_8ef40b1e64cc4ea692464a33';
const legacy = { id: 'alert-1', reasons: [] };
const linked = {
  ...legacy,
  reasons: [{ code: 'CORRELATED_ENTITY', detail: 'Expediente del correlador: ' + id }],
};

describe('investigation evidence provenance', () => {
  it('opens the exact archive before the emitter has saved its alert ID', async () => {
    const get = vi.fn().mockResolvedValue({ status: 200, body: { id } });
    expect(await findEmittingCandidate(get, linked)).toEqual({ id });
    expect(get).toHaveBeenCalledWith('/v1/candidates/' + id);
  });

  it('resolves a historical alert by its emitted ID', async () => {
    const entry = { id, alertId: legacy.id };
    const get = vi.fn().mockResolvedValue({ status: 200, body: entry });
    expect(await findEmittingCandidate(get, legacy)).toEqual(entry);
    expect(get).toHaveBeenCalledWith('/v1/candidates-by-alert/alert-1');
  });

  it.each([linked, legacy])('rejects membership in a different case', async alert => {
    const get = vi.fn().mockResolvedValue({
      status: 200, body: { id, alertId: 'other', b89AlertIds: [alert.id] },
    });
    await expect(findEmittingCandidate(get, alert)).rejects.toThrow('CANDIDATE_REFERENCE_MISMATCH');
  });

  it('distinguishes absent evidence from an unavailable archive', async () => {
    const get = vi.fn().mockResolvedValueOnce({ status: 404 }).mockResolvedValueOnce({ status: 503 });
    expect(await findEmittingCandidate(get, legacy)).toBeUndefined();
    await expect(findEmittingCandidate(get, legacy)).rejects.toThrow('CORRELATOR_UNAVAILABLE');
  });
});
