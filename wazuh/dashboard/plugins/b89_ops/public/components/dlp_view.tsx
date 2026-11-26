/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * DLP de endpoints. Responde primero «¿qué equipos están protegidos y hay algo que atender?»;
 * después, conectar un equipo (asistente de 3 pasos) y qué detecta la política. Lo técnico
 * (IDs de regla, huellas SHA-256, reglas avanzadas) queda plegado o en tooltips.
 *
 * `lang="es-PE" translate="no"`: el dashboard declara la página en inglés y el traductor del
 * navegador convertía «Tokens de Slack» en «Accede a una holgura».
 */

import React, { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiConfirmModal,
  EuiFieldText,
  EuiIcon,
  EuiLoadingContent,
  EuiLoadingSpinner,
  EuiSwitch,
  EuiTextArea,
  EuiToolTip,
} from '@elastic/eui';
import { LOGOUT_PATH } from '../../common';
import { B89ApiError } from '../api/client';
import type { DlpEndpoint, DlpEnrollmentToken, DlpPolicy, DlpUsbControlGroup, DlpUsbControlPolicy } from '../api/dlp';
import {
  cancelDlpEnrollmentToken,
  createDlpEnrollmentToken,
  getDlpEndpoints,
  getDlpPolicy,
  revokeDlpEndpoint,
  saveDlpPolicy,
} from '../api/dlp';
import { B89Page, useConsole } from './console_context';
import type { FleetSummary, InstallInput, InstallOs, PolicyDiff, WizardState } from './dlp_model';
import {
  checkEnrollment,
  describeDiff,
  DLP_RULES,
  endpointHealth,
  hasChanges,
  HEALTH_ACTION,
  HEALTH_LABEL,
  HEALTH_TONE,
  installCommand,
  minutesLeft,
  missingInstallFields,
  nextVersion,
  parseFingerprints,
  policyDiff,
  rolloutProgress,
  sortEndpoints,
  summarizeFleet,
  normalizeUsbGroups,
  wizardReducer,
} from './dlp_model';
import { ErrorCallout, Mono, Timestamp } from './primitives';
import { FerrispectorMark } from './ferrispector_mark';
import { getDlpFindings } from '../api/dlp';
import type { DlpFindings, DlpWindow } from '../../common/dlp_findings';
import { detectorLabel } from './dlp_model';

// La lista se refresca cada 5 s (decisión del dueño, 9e3b05a): un equipo recién instalado aparece solo.
const ENDPOINT_POLL_MS = 5_000;
const ROLLOUT_POLL_MS = 5_000;
const ENROLLMENT_POLL_MS = 5_000;
const INSTALL_PREFS_KEY = 'b89.dlp.install';

const isStepUp = (error: unknown) => error instanceof B89ApiError && error.code === 'STEP_UP_REQUIRED';

function copy(text: string): Promise<boolean> {
  const clipboard = typeof navigator === 'undefined' ? undefined : navigator.clipboard;
  if (!clipboard) return Promise.resolve(false);
  return clipboard.writeText(text).then(() => true, () => false);
}

function readInstallPrefs(): Pick<InstallInput, 'os' | 'wazuhManager'> {
  try {
    const raw = window.localStorage.getItem(INSTALL_PREFS_KEY);
    const parsed = raw ? (JSON.parse(raw) as Partial<InstallInput>) : {};
    return {
      os: parsed.os === 'unix' ? 'unix' : 'windows',
      wazuhManager: typeof parsed.wazuhManager === 'string' ? parsed.wazuhManager.slice(0, 255) : '',
    };
  } catch {
    return { os: 'windows', wazuhManager: '' };
  }
}

function writeInstallPrefs(input: InstallInput) {
  try {
    window.localStorage.setItem(INSTALL_PREFS_KEY, JSON.stringify({ os: input.os, wazuhManager: input.wazuhManager }));
  } catch {
    // Solo es una comodidad: sin almacenamiento, la persona vuelve a escribir el servidor.
  }
}

// ======================================================================== piezas exportadas

/** Aviso de reautenticación: solo aparece junto a la acción que la pidió. */
export function StepUpNotice({ action, logoutHref, onDismiss }: { action: string; logoutHref: string; onDismiss?: () => void }) {
  return (
    <EuiCallOut color="warning" size="s" iconType="lock" title={`Para ${action}, vuelve a iniciar sesión`} className="b89Dlp__stepUp">
      <p>Por seguridad, esta acción pide un inicio de sesión de menos de 30 minutos.</p>
      <div className="b89Dlp__inlineActions">
        <EuiButton size="s" href={logoutHref}>Cerrar sesión y volver a entrar</EuiButton>
        {onDismiss && <EuiButtonEmpty size="s" onClick={onDismiss}>Ahora no</EuiButtonEmpty>}
      </div>
    </EuiCallOut>
  );
}

const INSTALLER_GROUPS = [
  { platform: 'windows', label: 'Windows', options: [{ arch: 'x64', label: '64 bits · Intel o AMD' }, { arch: 'arm64', label: 'ARM64' }] },
  { platform: 'macos', label: 'macOS', options: [{ arch: 'arm64', label: 'Apple Silicon' }, { arch: 'x64', label: 'Intel' }] },
  { platform: 'linux', label: 'Linux', options: [{ arch: 'x64', label: '64 bits · Intel o AMD' }, { arch: 'arm64', label: 'ARM64' }] },
] as const;

/** Descargas solo para administradores; cada paquete trae motor, reglas verificadas e instrucciones. */
function InstallerDownloads({ api, onPackageDownloaded }: {
  api: ReturnType<typeof useConsole>['api'];
  onPackageDownloaded: (platform: string, sha256: string) => void;
}) {
  const [downloading, setDownloading] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [downloaded, setDownloaded] = useState<{ filename: string; sha256: string } | null>(null);
  const download = async (platform: string, arch: string) => {
    const target = `${platform}-${arch}`;
    setDownloading(target);
    setError(null);
    try {
      const result = await api.download(`/dlp/installers/${target}`);
      setDownloaded({ filename: result.filename, sha256: result.sha256 });
      onPackageDownloaded(target, result.sha256);
      const url = URL.createObjectURL(result.blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = result.filename;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
    } catch (reason) {
      setError(reason);
    } finally {
      setDownloading(null);
    }
  };

  return (
    <section className="b89Panel b89Dlp__downloads" aria-labelledby="b89-dlp-downloads">
      <div className="b89Panel__header">
        <div>
          <h2 id="b89-dlp-downloads">Instalar RabbitDLP</h2>
          <p>Descarga el paquete para el equipo que vas a proteger. La clave de conexión se crea aparte.</p>
        </div>
      </div>
      {error && <ErrorCallout error={error} />}
      <div className="b89Dlp__downloadOptions">
        {INSTALLER_GROUPS.map((group) => (
          <details className="b89Dlp__downloadCard" key={group.platform}>
            <summary>
              <span>{group.label}</span>
              <span className="b89Muted">Elegir arquitectura</span>
            </summary>
            <div className="b89Dlp__downloadChoices">
              {group.options.map((option) => {
                const target = `${group.platform}-${option.arch}`;
                return (
                  <EuiButton
                    key={target}
                    size="s"
                    iconType="download"
                    isLoading={downloading === target}
                    isDisabled={Boolean(downloading)}
                    onClick={() => void download(group.platform, option.arch)}
                  >
                    {option.label}
                  </EuiButton>
                );
              })}
            </div>
          </details>
        ))}
      </div>
      {downloaded && <p className="b89Dlp__downloaded" role="status">{downloaded.filename} descargado. SHA-256: <Mono>{downloaded.sha256}</Mono></p>}
      <p className="b89Dlp__downloadNote">El paquete incluye el motor y las reglas iniciales. Instálalo con permisos de administrador y luego conecta el equipo con una clave de un solo uso.</p>
    </section>
  );
}

/** La respuesta primero: cuántos equipos están protegidos y si hay algo que atender. */
export function FleetStatus({
  summary,
  policy,
  endpointsError,
  stale,
  onRetry,
}: {
  summary: FleetSummary | null;
  policy: DlpPolicy | null;
  endpointsError: unknown;
  stale: boolean;
  onRetry: () => void;
}) {
  const unknown = summary === null;
  const tone = summary === null ? 'warning' : summary.tone;
  const parts: { key: string; tone: string; text: string }[] = [];
  if (summary) {
    const { counts } = summary;
    if (counts.ok) parts.push({ key: 'ok', tone: 'success', text: `${counts.ok} ${counts.ok === 1 ? 'protegido' : 'protegidos'}` });
    if (counts.updating) parts.push({ key: 'updating', tone: 'primary', text: `${counts.updating} aplicando cambios` });
    if (counts.offline + counts.never) parts.push({ key: 'offline', tone: 'warning', text: `${counts.offline + counts.never} sin conexión` });
    if (counts.reinstall) parts.push({ key: 'reinstall', tone: 'danger', text: `${counts.reinstall} por reinstalar` });
  }
  return (
    <section className={`b89Dlp__status b89Dlp__status--${tone}`} aria-labelledby="b89-dlp-status" aria-live="polite">
      <div>
        <h2 id="b89-dlp-status">{summary === null ? 'No se pudo consultar el estado de los equipos' : summary.headline}</h2>
        {parts.length > 0 && (
          <p className="b89Dlp__counts">
            {parts.map((part) => (
              <span key={part.key} className={`b89Dlp__count b89Dlp__count--${part.tone}`}>{part.text}</span>
            ))}
          </p>
        )}
        {(unknown || stale) && (
          <p className="b89Dlp__stale">
            {unknown
              ? endpointsError instanceof B89ApiError ? endpointsError.message : 'El servicio no respondió.'
              : 'No se pudo actualizar; se muestran los últimos datos recibidos.'}{' '}
            <EuiButtonEmpty size="xs" flush="left" onClick={onRetry}>Reintentar</EuiButtonEmpty>
          </p>
        )}
      </div>
      {policy && (
        <p className="b89Dlp__policyMeta">
          {policy.revision === 0
            ? 'Política inicial del paquete'
            : <>Política revisión {policy.revision} · <Timestamp iso={policy.updatedAt} /></>}
        </p>
      )}
    </section>
  );
}

function EndpointRow({ endpoint, policyRevision, usbControlEnabled, canConfigure, onRevoke }: {
  endpoint: DlpEndpoint;
  policyRevision: number | null;
  usbControlEnabled: boolean;
  canConfigure: boolean;
  onRevoke: (endpoint: DlpEndpoint) => void;
}) {
  const health = endpointHealth(endpoint);
  const action = HEALTH_ACTION[health];
  const lagging = health === 'updating' && policyRevision !== null && endpoint.currentRevision !== null;
  const usbStatus = endpoint.usbControlStatus ?? 'unknown';
  const usbLabel: Record<string, string> = {
    active: 'USB: Defender confirmó la política',
    pending: 'USB: aplicando política',
    unsupported: 'USB: Windows/Defender no compatible',
    conflict: 'USB: conflicto con otra política',
    error: 'USB: no se pudo aplicar',
    disabled: 'USB: sin bloqueo',
    'not-applicable': 'USB: no disponible en este sistema',
    unknown: 'USB: estado sin confirmar',
  };
  return (
    <tr data-health={health}>
      <th scope="row">
        <span className="b89Dlp__host" data-b89-no-translate="">{endpoint.hostname}</span>
      </th>
      <td>
        <EuiBadge color={HEALTH_TONE[health]}>{HEALTH_LABEL[health]}</EuiBadge>
        {lagging && <small>Tiene la revisión {endpoint.currentRevision}; la vigente es {policyRevision}.</small>}
        {action && <small>{action}</small>}
        {usbControlEnabled && <small>{usbLabel[usbStatus] ?? usbLabel.unknown}</small>}
      </td>
      <td>{health === 'never' ? <span className="b89Muted">Nunca</span> : <Timestamp iso={endpoint.lastSeenAt} />}</td>
      <td className="b89Dlp__rowAction">
        {canConfigure && health !== 'revoked' && (
          <EuiButtonEmpty size="xs" color="danger" onClick={() => onRevoke(endpoint)} aria-label={`Revocar ${endpoint.hostname}`}>
            Revocar
          </EuiButtonEmpty>
        )}
      </td>
    </tr>
  );
}

export function EndpointList({
  endpoints,
  policyRevision,
  usbControlEnabled = false,
  canConfigure,
  onRevoke,
  onConnect,
}: {
  endpoints: readonly DlpEndpoint[];
  policyRevision: number | null;
  usbControlEnabled?: boolean;
  canConfigure: boolean;
  onRevoke: (endpoint: DlpEndpoint) => void;
  onConnect?: () => void;
}) {
  const sorted = sortEndpoints(endpoints);
  const active = sorted.filter((endpoint) => endpointHealth(endpoint) !== 'revoked');
  const revoked = sorted.filter((endpoint) => endpointHealth(endpoint) === 'revoked');
  const table = (rows: readonly DlpEndpoint[]) => (
    <div className="b89TableScroll">
      <table className="b89Dlp__table">
        <thead>
          <tr>
            <th scope="col">Equipo</th>
            <th scope="col">Estado</th>
            <th scope="col">Último contacto</th>
            <th scope="col"><span className="b89VisuallyHidden">Acciones</span></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((endpoint) => (
            <EndpointRow key={endpoint.id} endpoint={endpoint} policyRevision={policyRevision} usbControlEnabled={usbControlEnabled} canConfigure={canConfigure} onRevoke={onRevoke} />
          ))}
        </tbody>
      </table>
    </div>
  );
  return (
    <section className="b89Panel" aria-labelledby="b89-dlp-endpoints">
      <div className="b89Panel__header">
        <h2 id="b89-dlp-endpoints">Equipos</h2>
      </div>
      {active.length === 0 ? (
        <p className="b89Dlp__empty">
          Aún no hay equipos conectados.
          {canConfigure && onConnect && (
            <EuiButtonEmpty size="s" onClick={onConnect}>Conectar el primero</EuiButtonEmpty>
          )}
        </p>
      ) : (
        table(active)
      )}
      {revoked.length > 0 && (
        <details className="b89Guide__details b89Dlp__more">
          <summary>Revocados ({revoked.length})</summary>
          {table(revoked)}
        </details>
      )}
    </section>
  );
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  useEffect(() => {
    if (state === 'idle') return undefined;
    const timer = window.setTimeout(() => setState('idle'), 2500);
    return () => window.clearTimeout(timer);
  }, [state]);
  return (
    <EuiButton
      size="s"
      iconType={state === 'copied' ? 'check' : 'copyClipboard'}
      onClick={() => void copy(text).then((ok) => setState(ok ? 'copied' : 'failed'))}
    >
      {state === 'copied' ? 'Copiado' : state === 'failed' ? 'Selecciónalo y copia' : label}
    </EuiButton>
  );
}

const STEP_TITLES = ['Crear una clave', 'Instalar en el equipo', 'Esperar a que aparezca'] as const;

function stepIndex(state: WizardState): number {
  if (state.step === 'create') return 0;
  if (state.step === 'waiting') return 1;
  return 2;
}

/** Asistente de 3 pasos: crear la clave, pegar el comando, esperar al equipo (se detecta solo). */
export function ConnectWizard({
  state,
  install,
  now,
  logoutHref,
  onInstallChange,
  onCreate,
  onCancel,
  onClose,
}: {
  state: WizardState;
  install: InstallInput;
  now: number;
  logoutHref: string;
  onInstallChange: (next: InstallInput) => void;
  onCreate: () => void;
  onCancel: () => void;
  onClose: () => void;
}) {
  if (state.step === 'closed') return null;
  const current = stepIndex(state);
  const missing = missingInstallFields(install);
  const command = installCommand(install);
  const set = (patch: Partial<InstallInput>) => onInstallChange({ ...install, ...patch });
  const token: DlpEnrollmentToken | null = state.step === 'waiting' ? state.token : null;
  return (
    <section className="b89Panel b89Dlp__wizard" aria-labelledby="b89-dlp-wizard">
      <div className="b89Panel__header">
        <h2 id="b89-dlp-wizard">Conectar un equipo</h2>
        {state.step !== 'waiting' && <EuiButtonEmpty size="s" onClick={onClose}>Cerrar</EuiButtonEmpty>}
      </div>
      <ol className="b89Dlp__steps">
        {STEP_TITLES.map((title, index) => (
          <li
            key={title}
            className={`b89Dlp__step${index === current ? ' b89Dlp__step--active' : ''}${index < current ? ' b89Dlp__step--done' : ''}`}
            aria-current={index === current ? 'step' : undefined}
          >
            <span className="b89Dlp__stepMark" aria-hidden="true">{index < current ? <EuiIcon type="check" size="s" /> : index + 1}</span>
            <span className="b89Dlp__stepTitle">{title}</span>
          </li>
        ))}
      </ol>

      {state.step === 'create' && (
        <div className="b89Dlp__stepBody">
          <p>La clave sirve para un solo equipo y vence en 30 minutos.</p>
          {state.stepUp && <StepUpNotice action="crear la clave" logoutHref={logoutHref} />}
          {state.error instanceof B89ApiError ? (
            <EuiCallOut
              color={state.error.code === 'DEPENDENCY_DEGRADED' ? 'warning' : 'danger'}
              iconType={state.error.code === 'DEPENDENCY_DEGRADED' ? 'alert' : 'cross'}
              size="s"
              title="No se pudo crear la clave de conexión"
            >
              <p>
                {state.error.code === 'DEPENDENCY_DEGRADED'
                  ? 'El servicio DLP o su base de datos no respondió. La clave no quedó activa. Reintenta en unos minutos.'
                  : state.error.code === 'RESOURCE_UNAVAILABLE'
                    ? 'No se pudo reservar la clave. Comprueba el permiso de administración de DLP y el límite de equipos; si continúa, comparte la referencia con Plataforma.'
                    : 'La solicitud no se completó. Revisa tu sesión y vuelve a intentarlo.'}
              </p>
              {state.error.correlationId && <p>Referencia: <Mono>{state.error.correlationId}</Mono></p>}
              <EuiButtonEmpty size="s" flush="left" onClick={onCreate}>Intentar de nuevo</EuiButtonEmpty>
            </EuiCallOut>
          ) : state.error ? <ErrorCallout error={state.error} /> : null}
          <EuiButton fill onClick={onCreate} isLoading={state.busy}>Crear clave</EuiButton>
        </div>
      )}

      {token && (
        <div className="b89Dlp__stepBody">
          <div className="b89Dlp__osPicker" role="group" aria-label="Sistema del equipo">
            {([['windows', 'Windows'], ['unix', 'macOS o Linux']] as const).map(([os, label]) => (
              <EuiButton
                key={os}
                size="s"
                fill={install.os === os}
                aria-pressed={install.os === os}
                onClick={() => set({ os: os as InstallOs })}
              >
                {label}
              </EuiButton>
            ))}
          </div>
          <div className="b89Dlp__fields">
            <label>
              <span>Carpeta que se revisará</span>
              <EuiFieldText
                compressed
                value={install.watchRoot}
                placeholder={install.os === 'windows' ? 'C:\\Datos\\Proyecto' : '/Users/ana/Proyecto'}
                onChange={(event) => set({ watchRoot: event.target.value })}
                aria-label="Carpeta que se revisará"
              />
            </label>
            {install.os === 'windows' && (
              <>
                <label>
                  <span>Servidor Wazuh</span>
                  <EuiFieldText compressed value={install.wazuhManager} onChange={(event) => set({ wazuhManager: event.target.value })} aria-label="Servidor Wazuh" />
                </label>
                <label>
                  <span>SHA-256 del paquete</span>
                  <EuiFieldText compressed value={install.packageSha256} onChange={(event) => set({ packageSha256: event.target.value })} aria-label="SHA-256 del paquete" />
                </label>
              </>
            )}
          </div>
          <p className="b89Dlp__hint">
            {install.os === 'windows'
              ? 'En PowerShell como administrador, dentro de la carpeta del paquete:'
              : 'En una terminal, dentro de la carpeta del paquete descomprimido:'}
          </p>
          <pre className="b89Dlp__command" data-b89-no-translate="">{command}</pre>
          <div className="b89Dlp__inlineActions">
            <CopyButton text={command} label="Copiar comando" />
            {missing.length > 0 && <span className="b89Dlp__missing">Falta {missing.join(', ')}.</span>}
          </div>
          <p className="b89Dlp__hint">Cuando el instalador pida la clave, pega esta:</p>
          <div className="b89Dlp__token">
            <Mono>{token.token}</Mono>
            <CopyButton text={token.token} label="Copiar clave" />
          </div>
          <p className="b89Dlp__waiting" role="status">
            <EuiLoadingSpinner size="m" /> Esperando al equipo… aparecerá aquí solo.{' '}
            <span className="b89Muted">La clave vence en {minutesLeft(token.expiresAt, now)} min.</span>
          </p>
          <EuiButtonEmpty size="s" color="danger" flush="left" onClick={onCancel}>Cancelar y anular la clave</EuiButtonEmpty>
        </div>
      )}

      {state.step === 'connected' && (
        <div className="b89Dlp__stepBody">
          <EuiCallOut color="success" iconType="check" size="s" title={`${state.hostname} se conectó`}>
            <p>Recibirá la política vigente en menos de un minuto.</p>
          </EuiCallOut>
          <div className="b89Dlp__inlineActions">
            <EuiButton fill size="s" onClick={onClose}>Listo</EuiButton>
            <EuiButtonEmpty size="s" onClick={onCreate}>Conectar otro equipo</EuiButtonEmpty>
          </div>
        </div>
      )}

      {state.step === 'expired' && (
        <div className="b89Dlp__stepBody">
          <EuiCallOut color="warning" size="s" title="La clave venció sin que el equipo se conectara">
            <p>Si el instalador mostró un error, revísalo y vuelve a intentar con una clave nueva.</p>
          </EuiCallOut>
          <EuiButton size="s" onClick={onCreate}>Crear otra clave</EuiButton>
        </div>
      )}
    </section>
  );
}

function RuleSwitch({ ruleId, label, hint, checked, disabled, onToggle }: {
  ruleId: string;
  label: string;
  hint: string;
  checked: boolean;
  disabled: boolean;
  onToggle: (id: string, on: boolean) => void;
}) {
  return (
    <li className="b89Dlp__rule">
      <EuiSwitch
        compressed
        label={label}
        checked={checked}
        disabled={disabled}
        onChange={(event) => onToggle(ruleId, event.target.checked)}
      />
      <EuiToolTip content={<>{hint}<br />ID: {ruleId}</>}>
        <EuiIcon type="iInCircle" color="subdued" tabIndex={0} aria-label={`Más información sobre ${label}`} />
      </EuiToolTip>
    </li>
  );
}

export function RulesPanel({
  rules,
  fingerprintsText,
  fingerprintError,
  quarantineExactFingerprints,
  canConfigure,
  onToggle,
  onFingerprintsChange,
  onQuarantineChange,
  onImport,
}: {
  rules: readonly string[];
  fingerprintsText: string;
  fingerprintError: string | null;
  quarantineExactFingerprints: boolean;
  canConfigure: boolean;
  onToggle: (id: string, on: boolean) => void;
  onFingerprintsChange: (text: string) => void;
  onQuarantineChange: (enabled: boolean) => void;
  onImport: (event: React.ChangeEvent<HTMLInputElement>) => void;
}) {
  const basic = DLP_RULES.filter((rule) => !rule.advanced);
  const advanced = DLP_RULES.filter((rule) => rule.advanced);
  const advancedOn = advanced.filter((rule) => rules.includes(rule.id)).length;
  const parsed = parseFingerprints(fingerprintsText);
  const renderRule = (rule: (typeof DLP_RULES)[number]) => (
    <RuleSwitch
      key={rule.id}
      ruleId={rule.id}
      label={rule.label}
      hint={rule.hint}
      checked={rules.includes(rule.id)}
      disabled={!canConfigure}
      onToggle={onToggle}
    />
  );
  return (
    <section className="b89Panel" aria-labelledby="b89-dlp-rules">
      <div className="b89Panel__header">
        <h2 id="b89-dlp-rules">Qué detecta</h2>
        <span className="b89Panel__meta">{rules.length} de {DLP_RULES.length} reglas activas</span>
      </div>
      <ul className="b89Dlp__rules">{basic.map(renderRule)}</ul>
      <details className="b89Guide__details b89Dlp__more" open={advancedOn > 0 ? true : undefined}>
        <summary>Reglas avanzadas · {advancedOn} de {advanced.length} activas</summary>
        <p className="b89Dlp__hint">Pueden dar falsos positivos. DNI y RUC son datos personales: actívalos solo con aprobación de privacidad.</p>
        <ul className="b89Dlp__rules">{advanced.map(renderRule)}</ul>
      </details>
      <details className="b89Guide__details b89Dlp__more">
        <summary>Documentos específicos · {parsed.values.length}</summary>
        <p className="b89Dlp__hint">Alerta cuando aparece una copia exacta de un documento. Pega su huella SHA-256, una por línea; el documento nunca sale del equipo.</p>
        {canConfigure && (
          <label className="b89Dlp__import">
            <span>Importar desde .txt</span>
            <input type="file" accept=".txt,text/plain" onChange={onImport} />
          </label>
        )}
        <div className="b89Dlp__actionSetting">
          <EuiSwitch
            compressed
            label="Poner en cuarentena copias exactas detectadas"
            checked={quarantineExactFingerprints}
            disabled={!canConfigure || parsed.values.length === 0}
            onChange={(event) => onQuarantineChange(event.target.checked)}
          />
          <p className="b89Dlp__hint">
            Solo actúa sobre huellas SHA-256 de esta lista. El archivo se mueve a una carpeta local protegida y se puede restaurar con permisos de administrador. Las coincidencias de reglas de contenido siguen siendo alertas.
          </p>
        </div>
        <EuiTextArea
          aria-label="Huellas SHA-256, una por línea"
          value={fingerprintsText}
          readOnly={!canConfigure}
          onChange={(event) => onFingerprintsChange(event.target.value)}
          rows={6}
          resize="vertical"
          fullWidth
          isInvalid={Boolean(fingerprintError) || parsed.invalid.length > 0}
          placeholder={canConfigure ? 'Una huella SHA-256 por línea' : 'Sin documentos registrados'}
        />
        {parsed.invalid.length > 0 && (
          <p className="b89Dlp__error">
            {parsed.invalid.length === 1 ? 'La línea' : 'Las líneas'} {parsed.invalid.slice(0, 8).join(', ')}
            {parsed.invalid.length > 8 ? '…' : ''} no {parsed.invalid.length === 1 ? 'es una huella válida' : 'son huellas válidas'} (64 caracteres 0-9, a-f).
          </p>
        )}
      </details>
      {fingerprintError && <p className="b89Dlp__error" role="alert">{fingerprintError}</p>}
    </section>
  );
}

export function UsbControlPanel({
  policy,
  canConfigure,
  validationError,
  onChange,
}: {
  policy: DlpUsbControlPolicy;
  canConfigure: boolean;
  validationError: string | null;
  onChange: (policy: DlpUsbControlPolicy) => void;
}) {
  const updateGroup = (id: string, update: Partial<DlpUsbControlGroup>) => onChange({
    ...policy,
    allowedGroups: policy.allowedGroups.map((group) => group.id === id ? { ...group, ...update } : group),
  });
  return (
    <section className="b89Panel" aria-labelledby="b89-dlp-usb">
      <div className="b89Panel__header">
        <h2 id="b89-dlp-usb">Control de USB</h2>
        <span className="b89Panel__meta">Grupos administrados por B89 SOC</span>
      </div>
      <p>RabbitDLP aplicará Device Control de Microsoft Defender en Windows. Los SIDs permitidos podrán usar almacenamiento extraíble; los demás quedarán bloqueados. Las cuentas siguen activas: se restringe el USB, no el inicio de sesión.</p>
      <p className="b89Dlp__hint">B89 recibe el estado de la política, no cada intento USB. Defender registra los bloqueos en su informe Device control; el SOC puede consultarlos en Microsoft Defender.</p>
      {validationError && <EuiCallOut color="danger" size="s" title="Revisa los grupos USB"><p>{validationError}</p></EuiCallOut>}
      <EuiSwitch
        compressed
        label="Activar bloqueo USB por identidad"
        checked={policy.enabled}
        disabled={!canConfigure}
        onChange={(event) => onChange({ ...policy, enabled: event.target.checked })}
      />
      <EuiCallOut color="warning" size="s" title="Requisito de Windows">
        <p>Se necesita Microsoft Defender for Endpoint Plan 1/2 o Defender for Business y una política local sin conflictos con Intune o GPO. La consola no puede validar licencias: compruébalas antes de habilitar. B89 reportará por equipo si el motor aceptó la política.</p>
        <EuiSwitch
          compressed
          label="Confirmo que los equipos tienen Defender compatible y que B89 administrará su política USB local"
          checked={policy.supportedPlanConfirmed}
          disabled={!canConfigure || policy.enabled}
          onChange={(event) => onChange({ ...policy, supportedPlanConfirmed: event.target.checked })}
        />
      </EuiCallOut>
      <div className="b89Dlp__usbGroups">
        <div className="b89Dlp__panelActions">
          <strong>Identidades permitidas</strong>
          {canConfigure && <EuiButtonEmpty size="s" iconType="plusInCircle" onClick={() => onChange({
            ...policy,
            allowedGroups: [...policy.allowedGroups, { id: crypto.randomUUID(), name: '', identities: [] }],
          })}>Agregar grupo</EuiButtonEmpty>}
        </div>
        {policy.allowedGroups.length === 0 && <p className="b89Dlp__hint">Agrega al menos un grupo permitido antes de activar el bloqueo, para evitar bloquear el USB a todas las cuentas.</p>}
        {policy.allowedGroups.map((group) => (
          <div className="b89Dlp__usbGroup" key={group.id}>
            <div className="b89Dlp__panelActions">
              <EuiFieldText
                aria-label="Nombre del grupo USB"
                value={group.name}
                readOnly={!canConfigure}
                placeholder="Ej. Personal de soporte"
                onChange={(event) => updateGroup(group.id, { name: event.target.value })}
              />
              {canConfigure && <EuiButtonEmpty size="s" color="danger" onClick={() => onChange({
                ...policy,
                allowedGroups: policy.allowedGroups.filter((candidate) => candidate.id !== group.id),
              })}>Eliminar grupo</EuiButtonEmpty>}
            </div>
            <EuiTextArea
              aria-label={`SIDs autorizados de ${group.name || 'grupo USB'}`}
              value={group.identities.join('\n')}
              readOnly={!canConfigure}
              rows={3}
              resize="vertical"
              fullWidth
              placeholder="Un SID de Windows por línea, ej. S-1-5-21-…"
              onChange={(event) => updateGroup(group.id, { identities: event.target.value.split(/\r?\n/u).map((item) => item.trim()).filter(Boolean) })}
            />
          </div>
        ))}
      </div>
      <p className="b89Dlp__hint">Usa el SID de un usuario o grupo local/Active Directory. En Windows puedes obtener el del usuario con <code>whoami /user</code>; el SID de un grupo se consulta en Active Directory. B89 no sincroniza membresías de usuarios.</p>
    </section>
  );
}

/** Aparece solo con cambios sin guardar y dice exactamente qué cambiará. */
export function SaveBar({
  diff,
  saving,
  stepUp,
  conflict,
  logoutHref,
  onSave,
  onDiscard,
  onReload,
  onDismissStepUp,
}: {
  diff: PolicyDiff;
  saving: boolean;
  stepUp: boolean;
  conflict: boolean;
  logoutHref: string;
  onSave: () => void;
  onDiscard: () => void;
  onReload: () => void;
  onDismissStepUp: () => void;
}) {
  if (!hasChanges(diff) && !conflict) return null;
  return (
    <div className="b89Dlp__saveBar" role="region" aria-label="Cambios sin guardar">
      {conflict ? (
        <EuiCallOut color="warning" size="s" title="Alguien guardó otra versión mientras editabas">
          <EuiButtonEmpty size="xs" flush="left" onClick={onReload}>Cargar la versión nueva (descarta tus cambios)</EuiButtonEmpty>
        </EuiCallOut>
      ) : (
        <>
          <div>
            <strong>Cambios sin guardar</strong>
            <ul className="b89Dlp__diff">
              {describeDiff(diff).map((line) => <li key={line}>{line}</li>)}
            </ul>
          </div>
          <div className="b89Dlp__inlineActions">
            <EuiButton fill size="s" onClick={onSave} isLoading={saving}>Guardar y enviar a los equipos</EuiButton>
            <EuiButtonEmpty size="s" onClick={onDiscard} disabled={saving}>Descartar</EuiButtonEmpty>
          </div>
        </>
      )}
      {stepUp && <StepUpNotice action="guardar" logoutHref={logoutHref} onDismiss={onDismissStepUp} />}
    </div>
  );
}

/** Después de guardar: qué cambió y cuántos equipos ya aplicaron la revisión. */
export function RolloutNotice({
  revision,
  changes,
  applied,
  total,
  onDismiss,
}: {
  revision: number;
  changes: readonly string[];
  applied: number;
  total: number;
  onDismiss: () => void;
}) {
  const done = total > 0 && applied >= total;
  const title = total === 0
    ? `Revisión ${revision} guardada. No hay equipos conectados que la reciban.`
    : done
      ? `Revisión ${revision} aplicada en ${total === 1 ? 'el equipo' : `los ${total} equipos`}`
      : `Revisión ${revision} guardada · ${applied} de ${total} ${total === 1 ? 'equipo la aplicó' : 'equipos la aplicaron'}`;
  return (
    <EuiCallOut color={done || total === 0 ? 'success' : 'primary'} size="s" iconType={done ? 'check' : 'clock'} title={title} className="b89Dlp__rollout">
      {changes.length > 0 && <ul className="b89Dlp__diff">{changes.map((line) => <li key={line}>{line}</li>)}</ul>}
      {!done && total > 0 && <p className="b89Muted">Los equipos en línea la reciben en menos de un minuto.</p>}
      <EuiButtonEmpty size="xs" flush="left" onClick={onDismiss}>Cerrar</EuiButtonEmpty>
    </EuiCallOut>
  );
}

const WINDOW_LABEL: Record<DlpWindow, string> = { '24h': '24 h', '7d': '7 días', '30d': '30 días' };

/** Enlace a Discover con una consulta KQL y el periodo elegido. */
function discoverHref(basePath: string, range: DlpWindow, query: string): string {
  const kql = query.replace(/'/gu, "!'");
  return `${basePath}/app/data-explorer/discover#?_g=(time:(from:now-${range},to:now))&_q=(query:(language:kuery,query:'${encodeURIComponent(kql)}'))`;
}

/** Qué encontró Ferrispector en el SIEM y qué equipos tienen el agente con fallas. */
export function FindingsPanel({
  findings,
  range,
  onRange,
  basePath,
}: {
  findings: DlpFindings | null;
  range: DlpWindow;
  onRange: (range: DlpWindow) => void;
  basePath: string;
}) {
  return (
    <section className="b89Panel" aria-labelledby="b89-dlp-findings">
      <div className="b89Panel__header">
        <h2 id="b89-dlp-findings">Qué encontró</h2>
        <span className="b89Dlp__windows" role="group" aria-label="Periodo">
          {(Object.keys(WINDOW_LABEL) as DlpWindow[]).map((value) => (
            <EuiButtonEmpty
              key={value}
              size="xs"
              aria-pressed={value === range}
              isSelected={value === range}
              onClick={() => onRange(value)}
            >
              {WINDOW_LABEL[value]}
            </EuiButtonEmpty>
          ))}
        </span>
      </div>
      {findings === null ? (
        <EuiLoadingContent lines={2} />
      ) : findings.readable === 'forbidden' ? (
        <p className="b89Dlp__hint">
          Tu rol no tiene permiso para ver los eventos del SIEM, así que no se pueden mostrar los hallazgos.
        </p>
      ) : findings.readable === 'error' ? (
        <p className="b89Dlp__hint">No se pudieron leer los hallazgos del SIEM. Vuelve a intentarlo en unos minutos.</p>
      ) : (
        <>
          <p className="b89Dlp__findingsHeadline">
            {findings.total === 0
              ? `Sin hallazgos en ${WINDOW_LABEL[range]}.`
              : `${findings.total} ${findings.total === 1 ? 'hallazgo' : 'hallazgos'} en ${WINDOW_LABEL[range]}`}
            {findings.byHost.length > 0
              ? ` · en ${findings.byHost.length} ${findings.byHost.length === 1 ? 'equipo' : 'equipos'}`
              : ''}
          </p>
          {findings.agentIssues.length > 0 && (
            <EuiCallOut
              size="s"
              color="warning"
              title={`${findings.agentIssues.length} ${findings.agentIssues.length === 1 ? 'equipo tiene' : 'equipos tienen'} fallas del agente`}
            >
              <ul className="b89Dlp__issues">
                {findings.agentIssues.map((issue) => (
                  <li key={`${issue.host}-${issue.ruleId}`}>
                    <strong data-b89-no-translate="">{issue.host}</strong>:{' '}
                    {issue.ruleId === '101114' ? 'no recibe la política' : 'no puede revisar archivos'}
                    {issue.last ? (
                      <>
                        {' · '}
                        <Timestamp iso={issue.last} focusable={false} />
                      </>
                    ) : null}
                  </li>
                ))}
              </ul>
            </EuiCallOut>
          )}
          {findings.total > 0 && (
            <div className="b89Dlp__findingsGrid">
              <div>
                <h3>Por tipo</h3>
                <ul className="b89Dlp__bars">
                  {findings.byDetector.map((item) => (
                    <li key={item.detector}>
                      <span>{detectorLabel(item.detector)}</span>
                      <strong className="b89Tabular">{item.count}</strong>
                    </li>
                  ))}
                </ul>
              </div>
              <div>
                <h3>Por equipo</h3>
                <ul className="b89Dlp__bars">
                  {findings.byHost.map((item) => (
                    <li key={item.host}>
                      <a
                        href={discoverHref(basePath, range, `rule.groups:b89_dlp and agent.name:"${item.host}"`)}
                        data-b89-no-translate=""
                      >
                        {item.host}
                      </a>
                      <strong className="b89Tabular">{item.count}</strong>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
          {findings.latest.length > 0 && (
            <details className="b89Guide__details b89Dlp__more">
              <summary>Últimos hallazgos ({findings.latest.length})</summary>
              <div className="b89TableScroll">
                <table className="b89Dlp__table">
                  <thead>
                    <tr>
                      <th scope="col">Cuándo</th>
                      <th scope="col">Equipo</th>
                      <th scope="col">Qué</th>
                      <th scope="col">Archivo</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.latest.map((finding) => (
                      <tr key={finding.id || `${finding.at}-${finding.sha256 ?? ''}`}>
                        <td>
                          <Timestamp iso={finding.at} focusable={false} />
                        </td>
                        <th scope="row" data-b89-no-translate="">
                          {finding.host}
                        </th>
                        <td>{detectorLabel(finding.detector)}</td>
                        <td>
                          {finding.extension ?? 'sin extensión'}
                          {finding.sha256 && (
                            <small>
                              Huella: <Mono title={finding.sha256}>{finding.sha256.slice(0, 12)}…</Mono>
                            </small>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <a className="b89InlineLink" href={discoverHref(basePath, range, 'rule.groups:b89_dlp')}>
                Ver todos en el SIEM
              </a>
            </details>
          )}
        </>
      )}
    </section>
  );
}

function FindingsLoader({ basePath }: { basePath: string }) {
  const [range, setRange] = useState<DlpWindow>('7d');
  const [findings, setFindings] = useState<DlpFindings | null>(null);
  useEffect(() => {
    let active = true;
    setFindings(null);
    const load = () =>
      void getDlpFindings(basePath, range).then((result) => {
        if (active) setFindings(result);
      });
    load();
    const timer = globalThis.setInterval(load, 60_000);
    return () => {
      active = false;
      globalThis.clearInterval(timer);
    };
  }, [basePath, range]);
  return <FindingsPanel findings={findings} range={range} onRange={setRange} basePath={basePath} />;
}

// ======================================================================== pantalla

export function DlpView() {
  const { api, can, basePath } = useConsole();
  const canRead = can('dlp.read');
  const canConfigure = can('dlp.configure');
  const logoutHref = `${basePath}${LOGOUT_PATH}`;

  const [policy, setPolicy] = useState<DlpPolicy | null>(null);
  const [policyError, setPolicyError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [endpoints, setEndpoints] = useState<readonly DlpEndpoint[] | null>(null);
  const [endpointsError, setEndpointsError] = useState<unknown>(null);

  const [rules, setRules] = useState<string[]>([]);
  const [fingerprintsText, setFingerprintsText] = useState('');
  const [quarantineExactFingerprints, setQuarantineExactFingerprints] = useState(false);
  const [usbControl, setUsbControl] = useState<DlpUsbControlPolicy>({ enabled: false, supportedPlanConfirmed: false, allowedGroups: [] });
  const [usbControlError, setUsbControlError] = useState<string | null>(null);
  const [fingerprintError, setFingerprintError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveStepUp, setSaveStepUp] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [rollout, setRollout] = useState<{ revision: number; changes: string[]; at: number } | null>(null);

  const [wizard, dispatch] = useReducer(wizardReducer, { step: 'closed' } as WizardState);
  const [install, setInstall] = useState<InstallInput>(() => ({
    ...readInstallPrefs(),
    controlPlaneUrl: typeof window === 'undefined' ? '' : window.location.origin,
    watchRoot: '',
    packageSha256: '',
  }));
  const [now, setNow] = useState(() => Date.now());

  const [revokeTarget, setRevokeTarget] = useState<DlpEndpoint | null>(null);
  const [revoking, setRevoking] = useState(false);
  const [revokeStepUp, setRevokeStepUp] = useState(false);
  const [actionError, setActionError] = useState<unknown>(null);

  const applyPolicy = (data: DlpPolicy) => {
    setPolicy(data);
    setRules([...data.enabledRuleIds]);
    setFingerprintsText(data.fingerprintsSha256.join('\n'));
    setQuarantineExactFingerprints(data.quarantineExactFingerprints);
    setUsbControl(data.usbControl);
    setFingerprintError(null);
    setConflict(false);
  };

  const loadPolicy = useCallback(async () => {
    setPolicyError(null);
    try {
      applyPolicy(await getDlpPolicy(api));
    } catch (error) {
      setPolicyError(error);
    } finally {
      setLoading(false);
    }
  }, [api]);

  const loadEndpoints = useCallback(async () => {
    try {
      const result = await getDlpEndpoints(api);
      setEndpoints(result.items);
      setEndpointsError(null);
    } catch (error) {
      // Se conservan los datos anteriores: la pantalla pasa a «degradada», no a vacía.
      setEndpointsError(error);
    }
  }, [api]);

  useEffect(() => {
    if (!canRead) return;
    void loadPolicy();
    void loadEndpoints();
  }, [canRead, loadPolicy, loadEndpoints]);

  // Mientras una revisión recién guardada se distribuye, se consulta más seguido (5 min máx.).
  const progress = policy && endpoints ? rolloutProgress(endpoints, policy.revision) : null;
  const fastPoll = Boolean(rollout && progress && progress.applied < progress.total && now - rollout.at < 5 * 60_000);
  useEffect(() => {
    if (!canRead) return undefined;
    const timer = window.setInterval(() => void loadEndpoints(), fastPoll ? ROLLOUT_POLL_MS : ENDPOINT_POLL_MS);
    return () => window.clearInterval(timer);
  }, [canRead, fastPoll, loadEndpoints]);

  // Reloj para la cuenta regresiva de la clave y la ventana de sondeo rápido.
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 15_000);
    return () => window.clearInterval(timer);
  }, []);
  useEffect(() => dispatch({ type: 'tick', now }), [now]);

  // Paso 3: detectar solo cuándo el equipo usa la clave.
  const waitingId = wizard.step === 'waiting' ? wizard.token.id : null;
  const mounted = useRef(true);
  useEffect(() => () => { mounted.current = false; }, []);
  useEffect(() => {
    if (!waitingId) return undefined;
    let cancelled = false;
    const poll = async () => {
      const status = await checkEnrollment(api, waitingId);
      if (cancelled) return;
      dispatch({ type: 'status', status });
      if (status.state === 'connected') void loadEndpoints();
    };
    const timer = window.setInterval(() => void poll(), ENROLLMENT_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [api, waitingId, loadEndpoints]);

  const parsed = useMemo(() => parseFingerprints(fingerprintsText), [fingerprintsText]);
  const diff = useMemo(
    () => (policy ? policyDiff(policy, rules, parsed.values, quarantineExactFingerprints, usbControl) : {
      enabled: [], disabled: [], fingerprintsAdded: 0, fingerprintsRemoved: 0, quarantineChanged: false, usbControlChanged: false,
    }),
    [policy, rules, parsed.values, quarantineExactFingerprints, usbControl],
  );
  const summary = endpoints ? summarizeFleet(endpoints) : null;

  const createToken = async () => {
    dispatch({ type: 'creating' });
    try {
      const token = await createDlpEnrollmentToken(api);
      if (mounted.current) dispatch({ type: 'created', token });
    } catch (error) {
      if (mounted.current) dispatch({ type: 'createFailed', error });
    }
  };

  const cancelToken = async () => {
    if (wizard.step !== 'waiting') return;
    const id = wizard.token.id;
    setActionError(null);
    dispatch({ type: 'close' });
    try {
      await cancelDlpEnrollmentToken(api, id);
    } catch (error) {
      // Si ya se usó o venció, no hay nada que anular; cualquier otro error se muestra.
      if (!(error instanceof B89ApiError && error.code === 'RESOURCE_UNAVAILABLE')) setActionError(error);
      void loadEndpoints();
    }
  };

  const updateInstall = (next: InstallInput) => {
    setInstall(next);
    writeInstallPrefs(next);
  };

  const save = async () => {
    if (!policy) return;
    if (parsed.invalid.length > 0) {
      setFingerprintError('Corrige las huellas marcadas antes de guardar.');
      return;
    }
    if (quarantineExactFingerprints && parsed.values.length === 0) {
      setFingerprintError('Agrega al menos una huella exacta o desactiva la cuarentena.');
      return;
    }
    if (rules.length === 0 && parsed.values.length === 0 && !usbControl.enabled) {
      setFingerprintError('Activa al menos una regla o agrega un documento.');
      return;
    }
    const normalizedGroups = normalizeUsbGroups(usbControl.allowedGroups);
    if (normalizedGroups.some((group) => !group.name || group.name.length > 64)) {
      setUsbControlError('Cada grupo necesita un nombre de 1 a 64 caracteres.');
      return;
    }
    if (normalizedGroups.some((group) => group.identities.some((sid) => !/^S-1-(?:\d+-){1,14}\d+$/iu.test(sid)))) {
      setUsbControlError('Usa SIDs de Windows válidos en cada grupo. Puedes consultarlos en Windows con whoami /user o en las propiedades de Active Directory.');
      return;
    }
    if (usbControl.enabled && !usbControl.supportedPlanConfirmed) {
      setUsbControlError('Confirma que los equipos tienen Defender compatible antes de activar el bloqueo.');
      return;
    }
    if (usbControl.enabled && (normalizedGroups.length === 0 || normalizedGroups.some((group) => group.identities.length === 0))) {
      setUsbControlError('Agrega al menos un SID a cada grupo permitido antes de activar el bloqueo.');
      return;
    }
    setUsbControlError(null);
    const changes = describeDiff(diff);
    setActionError(null);
    setSaving(true);
    setFingerprintError(null);
    setSaveStepUp(false);
    try {
      const updated = await saveDlpPolicy(api, {
        expectedRevision: policy.revision,
        policyVersion: nextVersion(policy.policyVersion),
        enabledRuleIds: rules,
        fingerprintsSha256: parsed.values,
        quarantineExactFingerprints,
        usbControl: { ...usbControl, allowedGroups: normalizedGroups },
      });
      applyPolicy(updated);
      setRollout({ revision: updated.revision, changes, at: Date.now() });
      void loadEndpoints();
    } catch (error) {
      if (error instanceof B89ApiError && error.code === 'STATE_CONFLICT') setConflict(true);
      else if (isStepUp(error)) setSaveStepUp(true);
      else setActionError(error);
    } finally {
      setSaving(false);
    }
  };

  const confirmRevoke = async () => {
    if (!revokeTarget) return;
    setActionError(null);
    setRevoking(true);
    try {
      await revokeDlpEndpoint(api, revokeTarget.id);
      setRevokeTarget(null);
      void loadEndpoints();
    } catch (error) {
      setRevokeTarget(null);
      if (isStepUp(error)) setRevokeStepUp(true);
      else setActionError(error);
    } finally {
      setRevoking(false);
    }
  };

  const importFile = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = '';
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const text = typeof reader.result === 'string' ? reader.result : '';
      setFingerprintsText((previous) => [previous.trim(), text.trim()].filter(Boolean).join('\n'));
      setFingerprintError(null);
    };
    reader.onerror = () => setFingerprintError('No se pudo leer el archivo. Usa un .txt con una huella por línea.');
    reader.readAsText(file);
  };

  if (!canRead) {
    return (
      <B89Page title="DLP de endpoints">
        <div lang="es-PE" translate="no">
          <EuiCallOut color="warning" title="Tu rol no tiene acceso a DLP">
            <p>Pide al administrador el acceso de lectura de DLP.</p>
          </EuiCallOut>
        </div>
      </B89Page>
    );
  }

  const openWizard = () => dispatch({ type: 'open' });

  return (
    <B89Page
      title="DLP de endpoints"
      icon={<FerrispectorMark size={30} basePath={basePath} />}
      actions={canConfigure
        ? wizard.step === 'closed' && <EuiButton fill iconType="plusInCircle" onClick={openWizard}>Conectar un equipo</EuiButton>
        : <EuiBadge color="hollow">Solo lectura</EuiBadge>}
    >
      <div className="b89Dlp" lang="es-PE" translate="no">
        {policyError && <ErrorCallout error={policyError} onRetry={() => { void loadPolicy(); void loadEndpoints(); }} />}
        {Boolean(actionError) && <ErrorCallout error={actionError} />}

        <div className="b89Dlp__overview">
          {endpoints === null && !endpointsError ? (
            <EuiLoadingContent lines={2} />
          ) : (
            <FleetStatus
              summary={summary}
              policy={policy}
              endpointsError={endpointsError}
              stale={Boolean(endpointsError) && endpoints !== null}
              onRetry={() => void loadEndpoints()}
            />
          )}
          {canConfigure && (
            <InstallerDownloads
              api={api}
              onPackageDownloaded={(platform, sha256) => {
                if (platform.startsWith('windows-')) updateInstall({ ...install, packageSha256: sha256 });
              }}
            />
          )}
        </div>

        <FindingsLoader basePath={basePath} />

        {rollout && policy && progress && rollout.revision === policy.revision && (
          <RolloutNotice
            revision={rollout.revision}
            changes={rollout.changes}
            applied={progress.applied}
            total={progress.total}
            onDismiss={() => setRollout(null)}
          />
        )}

        {canConfigure && (
          <ConnectWizard
            state={wizard}
            install={install}
            now={now}
            logoutHref={logoutHref}
            onInstallChange={updateInstall}
            onCreate={() => void createToken()}
            onCancel={() => void cancelToken()}
            onClose={() => dispatch({ type: 'close' })}
          />
        )}

        {revokeStepUp && (
          <StepUpNotice action="revocar un equipo" logoutHref={logoutHref} onDismiss={() => setRevokeStepUp(false)} />
        )}

        {endpoints !== null && (
          <EndpointList
            endpoints={endpoints}
            policyRevision={policy?.revision ?? null}
            usbControlEnabled={policy?.usbControl.enabled ?? false}
            canConfigure={canConfigure}
            onRevoke={(endpoint) => { setRevokeStepUp(false); setRevokeTarget(endpoint); }}
            onConnect={wizard.step === 'closed' ? openWizard : undefined}
          />
        )}

        {loading && !policy ? (
          <EuiLoadingContent lines={4} />
        ) : policy && (
          <>
            <RulesPanel
              rules={rules}
              fingerprintsText={fingerprintsText}
              fingerprintError={fingerprintError}
              quarantineExactFingerprints={quarantineExactFingerprints}
              canConfigure={canConfigure}
              onToggle={(id, on) => setRules((current) => (on ? [...current.filter((rule) => rule !== id), id] : current.filter((rule) => rule !== id)))}
              onFingerprintsChange={(text) => { setFingerprintsText(text); setFingerprintError(null); }}
              onQuarantineChange={setQuarantineExactFingerprints}
              onImport={importFile}
            />
            <UsbControlPanel
              policy={usbControl}
              canConfigure={canConfigure}
              validationError={usbControlError}
              onChange={(next) => { setUsbControl({ ...next, allowedGroups: [...next.allowedGroups] }); setUsbControlError(null); }}
            />
            {canConfigure && (
              <SaveBar
                diff={diff}
                saving={saving}
                stepUp={saveStepUp}
                conflict={conflict}
                logoutHref={logoutHref}
                onSave={() => void save()}
                onDiscard={() => applyPolicy(policy)}
                onReload={() => void loadPolicy()}
                onDismissStepUp={() => setSaveStepUp(false)}
              />
            )}
          </>
        )}
      </div>

      {revokeTarget && (
        <EuiConfirmModal
          title={`¿Revocar ${revokeTarget.hostname}?`}
          onCancel={() => setRevokeTarget(null)}
          onConfirm={() => void confirmRevoke()}
          cancelButtonText="Cancelar"
          confirmButtonText="Revocar"
          buttonColor="danger"
          confirmButtonDisabled={revoking}
          defaultFocusedButton="cancel"
        >
          <p lang="es-PE" translate="no">
            El equipo dejará de recibir la política. RabbitDLP seguirá instalado; para quitarlo, desinstálalo en el equipo.
          </p>
        </EuiConfirmModal>
      )}
    </B89Page>
  );
}
