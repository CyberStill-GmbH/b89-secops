/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useEffect, useRef, useState } from 'react';
import {
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiCheckbox,
  EuiConfirmModal,
  EuiFieldText,
  EuiFormRow,
  EuiLoadingContent,
  EuiRadio,
  EuiSelect,
  EuiSpacer,
  EuiSwitch,
  EuiTextArea,
} from '@elastic/eui';
import {
  actionApplies,
  AI_CLOSE_BENIGN_GUARDS,
  AI_CLOSE_MAX_PRIORITIES,
  AI_INFERENCE_MIN_PRIORITIES,
  AI_MIN_CONFIDENCES,
  AI_MODE_NAME,
  AI_MODE_SUMMARY,
  AI_MODES,
  AI_REVIEW_STATUS_LABEL,
  AI_REVIEW_STATUSES,
  AI_SETTINGS_ACTION_HELP,
  AI_SETTINGS_ACTION_LABEL,
  AI_SETTINGS_ACTIONS,
  AI_SETTINGS_LIMITS,
  AiCloseMaxPriority,
  AiDigestMode,
  AiInferenceMinPriority,
  AiMinConfidence,
  AiSettingsAction,
  AiSettingsDraft,
  AiSettingsErrors,
  AiSettingsRisk,
  AnalystSettings,
  CAPABILITIES,
  draftFromSettings,
  draftsEqual,
  microUsdAmount,
  PRIORITIES,
  Priority,
  settingsFromDraft,
  settingsRisk,
} from '../../common';
import { getAiSettings, isAnalystUnavailable, saveAiSettings } from '../api/ai_investigations';
import { B89ApiError } from '../api/client';
import { ANALYST_UNAVAILABLE_TEXT, ANALYST_UNAVAILABLE_TITLE } from './ai_analyst_model';
import { RiskFlag } from './ai_analyst_parts';
import { useConsole } from './console_context';
import { ErrorCallout, Mono, Timestamp, useAsync } from './primitives';

type Patch = (patch: Partial<AiSettingsDraft>) => void;

function toggle<T>(items: readonly T[], item: T, on: boolean): T[] {
  const without = items.filter((value) => value !== item);
  return on ? [...without, item] : without;
}

function Group({
  id,
  title,
  description,
  hint,
  children,
}: {
  id: string;
  title: string;
  /** Para qué sirve la sección, en una o dos frases. */
  description: React.ReactNode;
  /** Aviso según el estado del borrador (p. ej. «en modo sombra no tiene efecto»). */
  hint?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="b89AiSetGroup" aria-labelledby={id}>
      <header className="b89AiSetGroup__intro">
        <h3 id={id} className="b89AiSetGroup__title">
          {title}
        </h3>
        <p className="b89AiSetGroup__description">{description}</p>
      </header>
      <div className="b89AiSetGroup__controls">
        {hint && <p className="b89AiSetGroup__hint">{hint}</p>}
        {children}
      </div>
    </section>
  );
}

function PriorityChecks({
  idPrefix,
  legend,
  value,
  options = PRIORITIES,
  disabled,
  error,
  onChange,
}: {
  idPrefix: string;
  legend: string;
  value: readonly Priority[];
  options?: readonly Priority[];
  disabled: boolean;
  error?: string;
  onChange: (next: Priority[]) => void;
}) {
  return (
    <fieldset className="b89Ai__checks" aria-invalid={error ? true : undefined}>
      <legend>{legend}</legend>
      <div className="b89Ai__checkRow">
        {options.map((priority) => (
          <EuiCheckbox
            key={priority}
            id={`${idPrefix}-${priority}`}
            label={priority}
            checked={value.includes(priority)}
            disabled={disabled}
            onChange={(event) => onChange(toggle(value, priority, event.target.checked))}
          />
        ))}
      </div>
      {error && (
        <p className="b89Ai__fieldError" role="alert">
          {error}
        </p>
      )}
    </fieldset>
  );
}

/** Consecuencia de las opciones que actúan sobre alertas reales sin una persona. */
export const AI_SETTINGS_RISK: Readonly<Partial<Record<AiSettingsAction | 'autonomous', string>>> = {
  autonomous:
    'Ejecuta por su cuenta las acciones permitidas sobre alertas reales, sin esperar a una persona.',
  acknowledge:
    'Cambia el estado de alertas reales: dejan de verse como nuevas aunque nadie las haya mirado.',
  closeBenign:
    'Cierra alertas reales sin revisión previa: una alerta mal clasificada sale de la cola abierta.',
};

/** Consecuencias de un cambio de riesgo, dichas sin rodeos antes de guardar. */
export function AiSettingsConfirmBody({ risk }: { risk: AiSettingsRisk }) {
  return (
    <>
      {risk.autonomous && (
        <>
          <p>
            <strong>Vas a activar el modo autónomo.</strong> El analista dejará de limitarse a
            recomendar: ejecutará por su cuenta las acciones que estén permitidas (escalar,
            reconocer, cerrar benignas conocidas) sobre alertas reales, sin esperar a una persona.
          </p>
          <p>Cada acción queda registrada en el expediente y siempre se avisa a una persona.</p>
        </>
      )}
      {risk.closeBenign && (
        <>
          <p>
            <strong>Vas a permitir el cierre de alertas benignas conocidas.</strong> En modo
            autónomo el analista cerrará alertas sin que nadie las revise antes. Estas condiciones
            no se pueden desactivar:
          </p>
          <ul className="b89Ai__guards">
            {AI_CLOSE_BENIGN_GUARDS.map((guard) => (
              <li key={guard}>{guard}</li>
            ))}
          </ul>
        </>
      )}
      <p>El cambio se aplica a las investigaciones que empiecen después de guardar.</p>
    </>
  );
}

/** Lo vigente (guardado), en una línea de etiquetas: se lee antes de tocar nada. */
export function AiSettingsSummary({ saved }: { saved: AnalystSettings }) {
  const ceiling = saved.budget.dailyCeilingMicroUsd;
  const autonomousActions =
    saved.mode === 'autonomous'
      ? AI_SETTINGS_ACTIONS.filter((action) => saved.actions[action]).map(
          (action) => AI_SETTINGS_ACTION_LABEL[action],
        )
      : [];
  return (
    <section className="b89AiSetSummary" aria-label="Configuración vigente">
      <span className="b89AiSetSummary__label">Vigente</span>
      <span className="b89AiSetSummary__chip" data-tone={saved.enabled ? 'ok' : 'neutral'}>
        {saved.enabled ? 'Analista activo' : 'Analista pausado'}
      </span>
      <span
        className="b89AiSetSummary__chip"
        data-tone={saved.mode === 'autonomous' ? 'risk' : 'neutral'}
      >
        Modo {AI_MODE_NAME[saved.mode].toLowerCase()}
      </span>
      <span className="b89AiSetSummary__chip">
        {ceiling === null
          ? 'IA apagada (solo reglas)'
          : `IA con techo de ${microUsdAmount(ceiling) ?? 'sin dato'} al día`}
      </span>
      {saved.mode === 'autonomous' && (
        <span className="b89AiSetSummary__chip" data-tone={autonomousActions.length > 0 ? 'risk' : 'neutral'}>
          {autonomousActions.length > 0
            ? `Actúa solo: ${autonomousActions.join(', ').toLowerCase()}`
            : 'Sin acciones autónomas activas'}
        </span>
      )}
    </section>
  );
}

/** Nombre visible de cada campo con error, para el resumen junto a «Guardar». */
const FIELD_LABEL: Readonly<Record<string, string>> = {
  'scope.priorities': 'Prioridades que investiga',
  'escalation.priorities': 'Prioridades que puede escalar',
  'closeBenign.minHistory': 'Historial mínimo del patrón',
  'budget.dailyCeilingMicroUsd': 'Techo diario',
  'budget.maxOutputTokens': 'Largo máximo de cada respuesta',
  'reports.digestHourLima': 'Hora del resumen',
  instructions: 'Indicaciones',
};

export function settingsErrorSummary(errors: AiSettingsErrors): string | null {
  const keys = Object.keys(errors);
  if (keys.length === 0) return null;
  const names = keys.map((key) => FIELD_LABEL[key] ?? 'Otro campo');
  return `Corrige: ${Array.from(new Set(names)).join(', ')}.`;
}

export function AiSettingsForm({
  saved,
  draft,
  errors,
  canEdit,
  dirty,
  busy,
  onChange,
  onSave,
  onDiscard,
  notice = null,
}: {
  saved: AnalystSettings;
  draft: AiSettingsDraft;
  errors: AiSettingsErrors;
  canEdit: boolean;
  dirty: boolean;
  busy: boolean;
  onChange: Patch;
  onSave: () => void;
  onDiscard: () => void;
  /** Aviso de guardado: va junto al botón «Guardar», donde la persona está mirando. */
  notice?: React.ReactNode;
}) {
  const locked = !canEdit || busy;
  const autonomous = draft.mode === 'autonomous';
  const escalationOff = locked || !autonomous || !draft.actions.escalate;
  const closeOff = locked || !autonomous || !draft.actions.closeBenign;
  const reviewOff = locked || draft.mode === 'shadow';
  const inferenceFieldsOff = locked || !draft.inferenceOn;
  const hasErrors = Object.keys(errors).length > 0;
  const remaining = AI_SETTINGS_LIMITS.instructionsMax - draft.instructions.length;

  return (
    <form
      className="b89AiSettings"
      aria-label="Configuración del Analista IA"
      onSubmit={(event) => {
        event.preventDefault();
        if (canEdit && dirty && !hasErrors && !busy) onSave();
      }}
    >
      {!canEdit && (
        <EuiCallOut size="s" iconType="lock" title="Solo lectura">
          <p>
            Puedes ver la configuración, pero cambiarla requiere la capacidad{' '}
            <Mono>{CAPABILITIES.investigationsConfigure}</Mono>.
          </p>
        </EuiCallOut>
      )}

      <AiSettingsSummary saved={saved} />

      <Group
        id="b89AiSetMode"
        title="Funcionamiento"
        description="Si el analista toma alertas nuevas y cuánto puede hacer sin una persona. Empieza en sombra y sube de modo cuando confíes en sus conclusiones."
      >
        <EuiSwitch
          label="Analista activo"
          checked={draft.enabled}
          disabled={locked}
          onChange={(event) => onChange({ enabled: event.target.checked })}
        />
        <p className="b89CellMeta">
          Desactivado no inicia investigaciones nuevas; las que ya existen se pueden consultar.
        </p>
        <fieldset className="b89Ai__checks">
          <legend>Modo de operación</legend>
          <div className="b89AiModes">
            {AI_MODES.map((mode) => (
              <div
                key={mode}
                className="b89AiModes__card"
                data-mode={mode}
                data-selected={draft.mode === mode ? 'true' : 'false'}
              >
                <EuiRadio
                  id={`b89AiMode-${mode}`}
                  name="b89AiMode"
                  label={
                    <span>
                      <strong>{AI_MODE_NAME[mode]}:</strong> {AI_MODE_SUMMARY[mode]}.
                    </span>
                  }
                  checked={draft.mode === mode}
                  disabled={locked}
                  onChange={() => onChange({ mode })}
                />
                {mode === 'autonomous' && <RiskFlag>{AI_SETTINGS_RISK.autonomous}</RiskFlag>}
              </div>
            ))}
          </div>
        </fieldset>
      </Group>

      <Group
        id="b89AiSetScope"
        title="Qué investiga"
        description="Qué alertas toma el analista y desde qué prioridad usa IA. Por debajo de ese umbral solo aplica reglas automáticas, sin costo."
      >
        <PriorityChecks
          idPrefix="b89AiScope"
          legend="Prioridades que se investigan"
          value={draft.scopePriorities}
          disabled={locked}
          error={errors['scope.priorities']}
          onChange={(scopePriorities) => onChange({ scopePriorities })}
        />
        <EuiFormRow
          label="Prioridad mínima para usar IA"
          helpText="Las alertas menos prioritarias se resuelven solo con reglas automáticas, sin usar IA."
        >
          <EuiSelect
            compressed
            value={draft.inferenceMinPriority}
            disabled={locked}
            options={AI_INFERENCE_MIN_PRIORITIES.map((value) => ({
              value,
              text: value === 'P1' ? 'Solo P1' : `${value} o más urgente`,
            }))}
            onChange={(event) =>
              onChange({ inferenceMinPriority: event.target.value as AiInferenceMinPriority })
            }
          />
        </EuiFormRow>
      </Group>

      <Group
        id="b89AiSetActions"
        title="Qué puede hacer por su cuenta"
        description="Acciones que el analista ejecuta sin esperar a una persona. Solo tienen efecto en modo autónomo (en asistido, únicamente pedir revisión)."
        hint={
          draft.mode === 'shadow'
            ? 'En modo sombra el analista no ejecuta acciones: estos permisos se conservan, pero no tienen efecto.'
            : draft.mode === 'assisted'
              ? 'En modo asistido solo puede pedir revisión humana: los demás permisos se conservan, pero no tienen efecto.'
              : 'En modo autónomo el analista ejecuta por su cuenta las acciones activadas.'
        }
      >
        <ul className="b89AiToggles">
          {AI_SETTINGS_ACTIONS.map((action) => {
            const risk = AI_SETTINGS_RISK[action];
            return (
              <li key={action} data-risk={risk ? 'true' : 'false'}>
                <EuiSwitch
                  label={AI_SETTINGS_ACTION_LABEL[action]}
                  checked={draft.actions[action]}
                  disabled={locked || !actionApplies(draft.mode, action)}
                  onChange={(event) =>
                    onChange({ actions: { ...draft.actions, [action]: event.target.checked } })
                  }
                />
                <p className="b89CellMeta">{AI_SETTINGS_ACTION_HELP[action]}</p>
                {risk && <RiskFlag>{risk}</RiskFlag>}
                {action === 'escalate' && (
                  <div className="b89AiToggles__nested">
                    <EuiFormRow label="Confianza mínima para escalar">
                      <EuiSelect
                        compressed
                        value={draft.escalationMinConfidence}
                        disabled={escalationOff}
                        options={AI_MIN_CONFIDENCES.map((value) => ({
                          value,
                          text: value === 'high' ? 'Alta' : 'Media o alta',
                        }))}
                        onChange={(event) =>
                          onChange({
                            escalationMinConfidence: event.target.value as AiMinConfidence,
                          })
                        }
                      />
                    </EuiFormRow>
                    <PriorityChecks
                      idPrefix="b89AiEscalation"
                      legend="Prioridades que se pueden escalar"
                      value={draft.escalationPriorities}
                      disabled={escalationOff}
                      error={errors['escalation.priorities']}
                      onChange={(escalationPriorities) => onChange({ escalationPriorities })}
                    />
                  </div>
                )}
                {action === 'closeBenign' && (
                  <div className="b89AiToggles__nested">
                    <div className="b89Ai__guardBox">
                      <p className="b89Ai__subhead">Condiciones que no se pueden desactivar</p>
                      <ul className="b89Ai__guards">
                        {AI_CLOSE_BENIGN_GUARDS.map((guard) => (
                          <li key={guard}>{guard}</li>
                        ))}
                      </ul>
                    </div>
                    <EuiFormRow label="Prioridad máxima que puede cerrar">
                      <EuiSelect
                        compressed
                        value={draft.closeMaxPriority}
                        disabled={closeOff}
                        options={AI_CLOSE_MAX_PRIORITIES.map((value) => ({
                          value,
                          text: value === 'P4' ? 'Solo P4' : 'P3 y P4',
                        }))}
                        onChange={(event) =>
                          onChange({ closeMaxPriority: event.target.value as AiCloseMaxPriority })
                        }
                      />
                    </EuiFormRow>
                    <EuiFormRow
                      label="Historial mínimo del patrón"
                      helpText={`Veces que el patrón ya se cerró como benigno (${AI_SETTINGS_LIMITS.minHistoryMin} a ${AI_SETTINGS_LIMITS.minHistoryMax}).`}
                      isInvalid={Boolean(errors['closeBenign.minHistory'])}
                      error={errors['closeBenign.minHistory']}
                    >
                      <EuiFieldText
                        compressed
                        inputMode="numeric"
                        value={draft.closeMinHistory}
                        disabled={closeOff}
                        isInvalid={Boolean(errors['closeBenign.minHistory'])}
                        onChange={(event) => onChange({ closeMinHistory: event.target.value })}
                      />
                    </EuiFormRow>
                  </div>
                )}
              </li>
            );
          })}
        </ul>
      </Group>

      <Group
        id="b89AiSetReview"
        title="Cuándo avisa a una persona"
        description="Qué investigaciones generan una notificación para que alguien del SOC las revise."
        hint={
          draft.mode === 'shadow'
            ? 'En modo sombra el analista no notifica: estas preferencias se conservan, pero no tienen efecto.'
            : undefined
        }
      >
        <PriorityChecks
          idPrefix="b89AiNotify"
          legend="Prioridades que notifican"
          value={draft.notifyPriorities}
          disabled={reviewOff}
          onChange={(notifyPriorities) => onChange({ notifyPriorities })}
        />
        <fieldset className="b89Ai__checks">
          <legend>Estados que notifican</legend>
          <div className="b89Ai__checkRow">
            {AI_REVIEW_STATUSES.map((status) => (
              <EuiCheckbox
                key={status}
                id={`b89AiNotifyStatus-${status}`}
                label={AI_REVIEW_STATUS_LABEL[status]}
                checked={draft.notifyOnStatuses.includes(status)}
                disabled={reviewOff}
                onChange={(event) =>
                  onChange({
                    notifyOnStatuses: toggle(draft.notifyOnStatuses, status, event.target.checked),
                  })
                }
              />
            ))}
          </div>
        </fieldset>
      </Group>

      <Group
        id="b89AiSetBudget"
        title="Presupuesto de IA"
        description="Cuánto puede gastar al día en IA. Sin techo diario no se usa IA: las investigaciones se resuelven solo con reglas automáticas."
      >
        <EuiSwitch
          label="Usar IA (con techo diario)"
          checked={draft.inferenceOn}
          disabled={locked}
          onChange={(event) => onChange({ inferenceOn: event.target.checked })}
        />
        <div className="b89AiSetGroup__fields">
          <EuiFormRow
            label="Techo diario (US$)"
            helpText="Gasto máximo por día. Costo aproximado; puede diferir de la factura."
            isInvalid={Boolean(errors['budget.dailyCeilingMicroUsd'])}
            error={errors['budget.dailyCeilingMicroUsd']}
          >
            <EuiFieldText
              compressed
              inputMode="decimal"
              placeholder="2,50"
              value={draft.dailyCeilingUsd}
              disabled={inferenceFieldsOff}
              isInvalid={Boolean(errors['budget.dailyCeilingMicroUsd'])}
              onChange={(event) => onChange({ dailyCeilingUsd: event.target.value })}
            />
          </EuiFormRow>
          <EuiFormRow
            label="Largo máximo de cada respuesta de la IA (tokens)"
            helpText="Opción avanzada: limita el largo y el costo de cada respuesta. Si no sabes qué valor usar, deja el actual."
            isInvalid={Boolean(errors['budget.maxOutputTokens'])}
            error={errors['budget.maxOutputTokens']}
          >
            <EuiFieldText
              compressed
              inputMode="numeric"
              value={draft.maxOutputTokens}
              disabled={inferenceFieldsOff}
              isInvalid={Boolean(errors['budget.maxOutputTokens'])}
              onChange={(event) => onChange({ maxOutputTokens: event.target.value })}
            />
          </EuiFormRow>
        </div>
        <EuiSwitch
          label="Permitir el nivel avanzado"
          checked={draft.advancedTierEnabled}
          disabled={inferenceFieldsOff}
          onChange={(event) => onChange({ advancedTierEnabled: event.target.checked })}
        />
        <p className="b89CellMeta">
          El nivel avanzado usa un modelo más capaz y más caro en los casos que lo ameritan.
        </p>
      </Group>

      <Group
        id="b89AiSetReports"
        title="Informes"
        description="Documentos que el analista deja para el equipo: uno por investigación y un resumen diario opcional."
      >
        <EuiSwitch
          label="Generar un informe por investigación"
          checked={draft.reportsPerRun}
          disabled={locked}
          onChange={(event) => onChange({ reportsPerRun: event.target.checked })}
        />
        <div className="b89AiSetGroup__fields">
          <EuiFormRow label="Resumen periódico">
            <EuiSelect
              compressed
              value={draft.digest}
              disabled={locked}
              options={[
                { value: 'off', text: 'Desactivado' },
                { value: 'daily', text: 'Diario' },
              ]}
              onChange={(event) => onChange({ digest: event.target.value as AiDigestMode })}
            />
          </EuiFormRow>
          <EuiFormRow
            label="Hora del resumen (hora de Lima, 0 a 23)"
            isInvalid={Boolean(errors['reports.digestHourLima'])}
            error={errors['reports.digestHourLima']}
          >
            <EuiFieldText
              compressed
              inputMode="numeric"
              value={draft.digestHourLima}
              disabled={locked || draft.digest === 'off'}
              isInvalid={Boolean(errors['reports.digestHourLima'])}
              onChange={(event) => onChange({ digestHourLima: event.target.value })}
            />
          </EuiFormRow>
        </div>
      </Group>

      <Group
        id="b89AiSetInstructions"
        title="Indicaciones del administrador"
        description="Orienta la redacción y las prioridades del analista. No puede conceder permisos ni saltarse los límites de esta configuración."
      >
        <EuiFormRow
          label="Indicaciones"
          helpText={
            remaining >= 0
              ? `${remaining} caracteres disponibles de ${AI_SETTINGS_LIMITS.instructionsMax}.`
              : undefined
          }
          isInvalid={Boolean(errors.instructions)}
          error={errors.instructions ? `${errors.instructions} Sobran ${-remaining}.` : undefined}
          fullWidth
        >
          <EuiTextArea
            fullWidth
            rows={5}
            value={draft.instructions}
            disabled={locked}
            isInvalid={Boolean(errors.instructions)}
            data-b89-no-translate=""
            onChange={(event) => onChange({ instructions: event.target.value })}
          />
        </EuiFormRow>
      </Group>

      <div className="b89AiSettings__foot" data-dirty={dirty ? 'true' : 'false'}>
        <p className="b89CellMeta">
          Versión <Mono>{String(saved.revision)}</Mono> · última modificación{' '}
          <Timestamp iso={saved.updatedAt} />
          {saved.updatedBy && (
            <>
              {' por '}
              <span data-b89-no-translate="">{saved.updatedBy}</span>
            </>
          )}
        </p>
        {notice}
        {canEdit && (
          <div className="b89Ai__actions">
            {dirty && (
              <span className="b89AiSettings__dirty" role="status">
                {hasErrors ? settingsErrorSummary(errors) : 'Hay cambios sin guardar.'}
              </span>
            )}
            <EuiButtonEmpty size="s" isDisabled={!dirty || busy} onClick={onDiscard}>
              Descartar cambios
            </EuiButtonEmpty>
            <EuiButton
              size="s"
              fill
              type="submit"
              isLoading={busy}
              isDisabled={!dirty || hasErrors}
              data-test-subj="b89AiSaveSettings"
            >
              Guardar configuración
            </EuiButton>
          </div>
        )}
      </div>
    </form>
  );
}

/** Rutas de campo que devolvió `VALIDATION_FAILED`, sin el prefijo `settings.`. */
export function serverFieldErrors(fields: readonly string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const field of fields.slice(0, 30)) {
    const path = field.replace(/^settings\./u, '');
    if (/^[A-Za-z][A-Za-z0-9_.[\]-]{0,80}$/u.test(path)) {
      out[path] = 'El servicio rechazó este valor.';
    }
  }
  return out;
}

/** El interruptor del despliegue manda sobre esta pantalla: sin él, nada de lo guardado corre. */
export function DeploymentOffCallout() {
  return (
    <EuiCallOut size="s" color="warning" iconType="alert" title={ANALYST_UNAVAILABLE_TITLE}>
      <p>
        Lo que guardes aquí se conserva, pero no se aplica hasta que se active.{' '}
        {ANALYST_UNAVAILABLE_TEXT}
      </p>
      <details className="b89AiDetails">
        <summary>Para administradores</summary>
        <p>
          Despliega con <code>B89_ANALYST_ENABLED=true</code> (valor por defecto del script de
          despliegue) y reinicia el servicio de la API.
        </p>
      </details>
    </EuiCallOut>
  );
}

export function AiSettingsTab({ onSaved }: { onSaved?: () => void }) {
  const { api, can } = useConsole();
  const loaded = useAsync(() => getAiSettings(api), [api]);
  const [saved, setSaved] = useState<AnalystSettings | null>(null);
  const [canConfigure, setCanConfigure] = useState(false);
  const [deploymentEnabled, setDeploymentEnabled] = useState<boolean | null>(null);
  const [draft, setDraft] = useState<AiSettingsDraft | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [rejected, setRejected] = useState<Record<string, string>>({});
  const [notice, setNotice] = useState<'saved' | 'conflict' | null>(null);
  const [confirm, setConfirm] = useState<AiSettingsRisk | null>(null);
  // El aviso de guardado está junto al botón; recibe el foco para que se anuncie y se vea.
  const savedRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (notice === 'saved' && savedRef.current) savedRef.current.focus();
  }, [notice]);

  useEffect(() => {
    if (!loaded.data) return;
    setSaved(loaded.data.settings);
    setCanConfigure(loaded.data.canConfigure);
    setDeploymentEnabled(loaded.data.deploymentEnabled);
    setDraft(draftFromSettings(loaded.data.settings));
    setRejected({});
  }, [loaded.data]);

  if (loaded.loading && !saved) return <EuiLoadingContent lines={6} />;
  if (!saved || !draft) {
    if (isAnalystUnavailable(loaded.error)) {
      return (
        <EuiCallOut color="warning" iconType="offline" title={ANALYST_UNAVAILABLE_TITLE}>
          <p>{ANALYST_UNAVAILABLE_TEXT}</p>
          <EuiButtonEmpty size="xs" flush="left" onClick={loaded.reload}>
            Volver a comprobar
          </EuiButtonEmpty>
        </EuiCallOut>
      );
    }
    return <ErrorCallout error={loaded.error} onRetry={loaded.reload} />;
  }

  const canEdit = canConfigure && can(CAPABILITIES.investigationsConfigure);
  const parsed = settingsFromDraft(draft);
  const dirty = !draftsEqual(draft, draftFromSettings(saved));
  // Los rechazos del servidor se muestran hasta que la persona vuelve a editar.
  const errors: AiSettingsErrors = { ...rejected, ...parsed.errors };
  const unplaced = Object.keys(rejected).filter(
    (path) =>
      ![
        'scope.priorities',
        'escalation.priorities',
        'closeBenign.minHistory',
        'budget.dailyCeilingMicroUsd',
        'budget.maxOutputTokens',
        'reports.digestHourLima',
        'instructions',
      ].includes(path),
  );

  const persist = async () => {
    if (!parsed.input) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const view = await saveAiSettings(api, parsed.input, saved.revision);
      setSaved(view.settings);
      setDeploymentEnabled(view.deploymentEnabled);
      setDraft(draftFromSettings(view.settings));
      setRejected({});
      setNotice('saved');
      if (onSaved) onSaved();
    } catch (failure) {
      if (failure instanceof B89ApiError && failure.code === 'STATE_CONFLICT') {
        // Otra persona guardó antes: se descarta el borrador y se muestra la versión vigente.
        setNotice('conflict');
        loaded.reload();
      } else {
        setError(failure);
        if (failure instanceof B89ApiError && failure.code === 'VALIDATION_FAILED') {
          setRejected(serverFieldErrors(failure.fields));
        }
      }
    } finally {
      setBusy(false);
      setConfirm(null);
    }
  };

  const save = () => {
    const risk = settingsRisk(saved, draft);
    if (risk.autonomous || risk.closeBenign) setConfirm(risk);
    else void persist();
  };

  return (
    <>
      {deploymentEnabled === false && (
        <>
          <DeploymentOffCallout />
          <EuiSpacer size="m" />
        </>
      )}
      {notice === 'conflict' && (
        <>
          <EuiCallOut
            size="s"
            color="warning"
            iconType="alert"
            title="Otra persona cambió la configuración mientras editabas"
          >
            <p role="alert">
              Tus cambios no se guardaron. Se cargó la versión vigente: revísala y vuelve a aplicar
              lo que necesites.
            </p>
          </EuiCallOut>
          <EuiSpacer size="m" />
        </>
      )}
      {error != null && (
        <>
          <ErrorCallout error={error} />
          {unplaced.length > 0 && (
            <p className="b89Ai__note">
              Campos observados por el servicio:{' '}
              {unplaced.map((path) => (
                <React.Fragment key={path}>
                  <Mono>{path}</Mono>{' '}
                </React.Fragment>
              ))}
            </p>
          )}
          <EuiSpacer size="m" />
        </>
      )}
      <AiSettingsForm
        saved={saved}
        draft={draft}
        errors={errors}
        canEdit={canEdit}
        dirty={dirty}
        busy={busy}
        onChange={(patch) => {
          setDraft({ ...draft, ...patch });
          setRejected({});
          setNotice(null);
        }}
        onSave={save}
        onDiscard={() => {
          setDraft(draftFromSettings(saved));
          setRejected({});
          setError(null);
        }}
        notice={
          notice === 'saved' ? (
            <div ref={savedRef} tabIndex={-1} className="b89AiSettings__saved">
              <EuiCallOut size="s" color="success" iconType="check" title="Configuración guardada">
                <p role="status">
                  <span className="b89AiSrOnly">Configuración guardada. </span>
                  {deploymentEnabled === false
                    ? 'Quedó guardada, pero no se aplicará hasta que el Analista IA se active en este entorno.'
                    : 'Se aplica a las investigaciones que empiecen desde ahora.'}
                </p>
              </EuiCallOut>
            </div>
          ) : null
        }
      />
      {confirm && (
        <EuiConfirmModal
          title={
            confirm.autonomous ? 'Activar el modo autónomo' : 'Permitir el cierre de benignas'
          }
          aria-label="Confirmar un cambio de riesgo en la configuración del analista"
          onCancel={() => setConfirm(null)}
          onConfirm={() => void persist()}
          cancelButtonText="Volver a revisar"
          confirmButtonText="Confirmar y guardar"
          buttonColor="danger"
          confirmButtonDisabled={busy}
          defaultFocusedButton="cancel"
        >
          <AiSettingsConfirmBody risk={confirm} />
        </EuiConfirmModal>
      )}
    </>
  );
}
