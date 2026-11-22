import { describe, expect, it } from 'vitest';
import { indexerUnavailableMessage } from './indexer_status';

describe('indexerUnavailableMessage', () => {
  it('explains that events could not be queried when the request fails', () => {
    expect(indexerUnavailableMessage({ failed: true, access: 'ok' })).toContain(
      'No pudimos consultar los eventos',
    );
    expect(indexerUnavailableMessage({ failed: false, access: 'error' })).toContain(
      'No pudimos consultar los eventos',
    );
  });

  it('explains permission denial and how to get access', () => {
    expect(indexerUnavailableMessage({ failed: false, access: 'forbidden' })).toContain(
      'Pide acceso al administrador',
    );
  });

  it('reports an empty period only after a successful, permitted query', () => {
    expect(indexerUnavailableMessage({ failed: false, access: 'ok' })).toBe(
      'No hay eventos disponibles para este período.',
    );
  });
});
