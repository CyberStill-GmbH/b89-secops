/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

export type IndexerAccess = 'ok' | 'forbidden' | 'error' | null | undefined;

/** Mensajes del resumen SOC que distinguen una consulta fallida de una consulta vacía. */
export function indexerUnavailableMessage(input: {
  readonly failed: boolean;
  readonly access: IndexerAccess;
}): string {
  if (input.failed || input.access === 'error') {
    return 'No pudimos consultar los eventos. Revisa el aviso de error de arriba o vuelve a intentar.';
  }
  if (input.access === 'forbidden') {
    return 'Tu rol no tiene permiso para consultar los eventos. Pide acceso al administrador.';
  }
  return 'No hay eventos disponibles para este período.';
}
