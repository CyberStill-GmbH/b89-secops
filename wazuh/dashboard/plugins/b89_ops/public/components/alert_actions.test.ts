/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import { alertActionPlan } from './alert_actions';

const ME = 'sub-me';
const ALL = { canTriage: true, canAssign: true, canOpenIncident: true };
const alert = (patch: Record<string, unknown>) =>
  ({ status: 'new', assigneeId: null, verdict: null, incidentId: null, ...patch }) as Parameters<
    typeof alertActionPlan
  >[0];

const primary = (plan: ReturnType<typeof alertActionPlan>) =>
  plan.actions.filter((action) => action.primary).map((action) => action.id);

describe('acciones de una alerta', () => {
  it('una sola acción principal por estado, en el orden del flujo', () => {
    expect(primary(alertActionPlan(alert({}), ME, ALL))).toEqual(['take']);
    expect(primary(alertActionPlan(alert({ status: 'acknowledged', assigneeId: ME }), ME, ALL))).toEqual(['classify']);
    expect(primary(alertActionPlan(alert({ status: 'acknowledged', assigneeId: 'otra' }), ME, ALL))).toEqual(['assign_me']);
    expect(primary(alertActionPlan(alert({ status: 'triaged', verdict: 'true_positive', assigneeId: ME }), ME, ALL))).toEqual(['escalate']);
    expect(primary(alertActionPlan(alert({ status: 'closed' }), ME, ALL))).toEqual(['reopen']);
  });

  it('nueva: tomarla basta para quedar responsable (sin un paso «asignarme» aparte)', () => {
    const plan = alertActionPlan(alert({}), ME, { ...ALL, canAssign: false });
    expect(plan.actions.map((action) => action.id)).toEqual(['take', 'open_incident']);
    expect(plan.hint).toBeNull();
  });

  it('sin permiso para asignarse, explica qué hacer en vez de esconder el paso', () => {
    const plan = alertActionPlan(alert({ status: 'acknowledged', assigneeId: 'otra' }), ME, { ...ALL, canAssign: false });
    expect(primary(plan)).toEqual([]);
    expect(plan.hint).toBe('Solo la persona responsable puede clasificarla. Pide a tu líder que te la asigne.');
  });

  it('solo lectura lo dice', () => {
    const plan = alertActionPlan(alert({}), ME, { ...ALL, canTriage: false });
    expect(plan.actions).toEqual([]);
    expect(plan.hint).toBe('Solo lectura: tu rol no puede cambiar alertas.');
  });

  it('no ofrece abrir incidente si ya tiene uno o está cerrada', () => {
    const ids = (patch: Record<string, unknown>) =>
      alertActionPlan(alert(patch), ME, ALL).actions.map((action) => action.id);
    expect(ids({ status: 'acknowledged', assigneeId: ME, incidentId: 'inc-1' })).not.toContain('open_incident');
    expect(ids({ status: 'closed' })).toEqual(['reopen']);
  });
});
