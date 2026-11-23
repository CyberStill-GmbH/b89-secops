/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

/**
 * «Lista blanca» (Tráfico de Cloudflare): quién puede llamar a la API de pagos y desde qué IPs.
 * Responde primero «¿cuántos están vigilados y hay algo que revisar?», después «¿esta IP es de
 * alguien?» y la lista filtrable. Los administradores editan en un borrador local y guardan todo de
 * una vez (compare-and-set sobre la revisión); la regla de alertas va plegada.
 *
 * `lang="es-PE" translate="no"`: el dashboard declara la página en inglés y el traductor del
 * navegador deformaba los textos.
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  EuiBadge,
  EuiBasicTable,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiConfirmModal,
  EuiFieldText,
  EuiFlyout,
  EuiFlyoutBody,
  EuiFlyoutFooter,
  EuiFlyoutHeader,
  EuiFormRow,
  EuiLoadingContent,
  EuiSelect,
  EuiTextArea,
  EuiTitle,
  EuiToolTip,
} from '@elastic/eui';
import type { EuiBasicTableColumn } from '@elastic/eui';
import { CAPABILITIES, LOGOUT_PATH } from '../../common';
import {
  ALLOWLIST_KINDS,
  ALLOWLIST_STATUSES,
  KIND_LABEL,
  STATUS_EFFECT,
  STATUS_LABEL,
} from '../../common/allowlist';
import type { AllowlistEntry, AllowlistResponse, AllowlistStatus } from '../../common/allowlist';
import { B89ApiError } from '../api/client';
import {
  allowlistAnswer,
  checkForm,
  DEFAULT_FILTER,
  describeChange,
  diffAllowlist,
  EMPTY_FORM,
  entryFromForm,
  entryId,
  filterCounts,
  filterEntries,
  formFromEntry,
  formIsValid,
  KIND_FILTER_LABEL,
  KIND_FILTERS,
  lookupIp,
  removeEntry,
  reviewReason,
  STATUS_FILTER_LABEL,
  STATUS_FILTERS,
  upsertEntry,
  validationMessage,
} from './allowlist_model';
import type { AllowlistChange, AllowlistFilter, EntryForm, FormCheck, IpLookup } from './allowlist_model';
import { useConsole } from './console_context';
import { ErrorCallout, Timestamp } from './primitives';

const PATH = '/cloudflare/allowlist';
const CHIPS_SHOWN = 3;
const CHANGES_SHOWN = 8;

const STATUS_COLOR: Readonly<Record<AllowlistStatus, string>> = {
  with_ip: 'primary',
  pending: 'warning',
  not_contacted: 'warning',
  to_validate: 'warning',
  not_required: 'hollow',
};

// ======================================================================== piezas exportadas

export function AllowlistNoAccess() {
  return (
    <div className="b89Allow" lang="es-PE" translate="no">
      <EuiCallOut color="primary" size="s" iconType="lock" title="Tu rol no puede ver la lista blanca">
        <p>Pide a un administrador el acceso de lectura de la lista blanca.</p>
      </EuiCallOut>
    </div>
  );
}

/** La respuesta primero: cuántas entradas se vigilan y si hay algo que revisar. */
export function AllowlistAnswerLine({
  entries,
  revision,
  updatedAt,
  canManage,
  onAdd,
  onReview,
}: {
  entries: readonly AllowlistEntry[];
  revision: number;
  updatedAt: string | null;
  canManage: boolean;
  onAdd?: () => void;
  onReview?: () => void;
}) {
  const answer = allowlistAnswer(entries);
  return (
    <div className="b89Allow__head">
      <div className="b89Allow__headText">
        <h2 className="b89Allow__answer" data-test-subj="b89AllowAnswer">
          {answer.headline}
        </h2>
        <p className="b89Allow__meta">
          {updatedAt ? (
            <>
              Guardada <Timestamp iso={updatedAt} /> · revisión {revision}
            </>
          ) : (
            'Lista inicial importada; aún nadie la guardó desde aquí.'
          )}
          {!canManage && (
            <>
              {' '}
              <EuiBadge color="hollow">Solo lectura</EuiBadge>
            </>
          )}
        </p>
        {answer.warning && (
          <p className="b89Allow__warning" role="note">
            <span aria-hidden="true">⚠ </span>
            {answer.warning}
            {onReview && (
              <>
                {' '}
                <EuiButtonEmpty size="xs" flush="left" onClick={onReview}>
                  Ver cuáles
                </EuiButtonEmpty>
              </>
            )}
          </p>
        )}
      </div>
      {canManage && onAdd && (
        <EuiButton fill size="s" iconType="plusInCircle" onClick={onAdd} data-test-subj="b89AllowAdd">
          Agregar cliente o proveedor
        </EuiButton>
      )}
    </div>
  );
}

/** Regla de alertas, plegada: se lee una vez. */
export function AllowlistRule() {
  return (
    <details className="b89Guide__details b89Allow__rule">
      <summary>¿Cómo decide B89 si una llamada es alerta?</summary>
      <ul>
        <li>
          Un cliente <strong>«Con IP»</strong> que llama a la API de pagos (apipayments.b89.io) desde una IP
          que no es suya es <strong>alerta crítica</strong>, sobre todo en login, pagos, payins y payouts.
        </li>
        <li>Los clientes sin IPs («No requiere», «Pendiente»…) nunca alertan, vengan de donde vengan.</li>
        <li>
          Los <strong>identificadores</strong> (opcionales) son textos que aparecen en sus peticiones, como su
          código de comercio en la URL: así B89 lo reconoce aunque llame desde una IP desconocida.
        </li>
      </ul>
    </details>
  );
}

export function IpLookupResult({ lookup }: { lookup: IpLookup }) {
  if (lookup.state === 'empty') return null;
  if (lookup.state === 'invalid') {
    return <p className="b89Allow__lookupResult">Escribe una IPv4 o IPv6 válida (p. ej. 34.199.50.40).</p>;
  }
  if (lookup.state === 'none') {
    return (
      <p className="b89Allow__lookupResult b89Allow__lookupResult--none">
        <strong>No está en la lista blanca:</strong> una petición a la API de pagos desde esta IP sería alerta
        crítica si trae el identificador de un cliente con IP.
      </p>
    );
  }
  return (
    <div className="b89Allow__lookupResult b89Allow__lookupResult--found">
      <strong>
        <code className="b89Allow__ip">{lookup.ip}</code> es de:
      </strong>
      <ul>
        {lookup.owners.map((owner) => (
          <li key={`${owner.entry.id}-${owner.environment}`}>
            {owner.entry.name} ({owner.environment}
            {owner.listed !== lookup.ip ? `, dentro de ${owner.listed}` : ''}) · {STATUS_LABEL[owner.entry.status]}
          </li>
        ))}
      </ul>
    </div>
  );
}

function FilterButtons<T extends string>({
  label,
  options,
  labels,
  counts,
  value,
  onChange,
}: {
  label: string;
  options: readonly T[];
  labels: Readonly<Record<T, string>>;
  counts: Readonly<Record<T, number>>;
  value: T;
  onChange: (next: T) => void;
}) {
  return (
    <div className="b89Allow__chips" role="group" aria-label={label}>
      {options.map((option) => (
        <button
          key={option}
          type="button"
          className="b89Allow__chip"
          aria-pressed={value === option}
          onClick={() => onChange(option)}
        >
          {labels[option]} <span className="b89Allow__chipCount">{counts[option]}</span>
        </button>
      ))}
    </div>
  );
}

export function AllowlistFilters({
  entries,
  filter,
  onChange,
}: {
  entries: readonly AllowlistEntry[];
  filter: AllowlistFilter;
  onChange: (next: AllowlistFilter) => void;
}) {
  const counts = filterCounts(entries, filter);
  return (
    <div className="b89Allow__filters">
      <FilterButtons
        label="Tipo"
        options={KIND_FILTERS}
        labels={KIND_FILTER_LABEL}
        counts={counts.kind}
        value={filter.kind}
        onChange={(kind) => onChange({ ...filter, kind })}
      />
      <FilterButtons
        label="Estado"
        options={STATUS_FILTERS}
        labels={STATUS_FILTER_LABEL}
        counts={counts.status}
        value={filter.status}
        onChange={(status) => onChange({ ...filter, status })}
      />
      <EuiFieldText
        className="b89Allow__search"
        compressed
        icon="search"
        placeholder="Buscar por nombre, IP, país…"
        aria-label="Buscar en la lista blanca por nombre, IP, país, producto o identificador"
        value={filter.query}
        onChange={(event) => onChange({ ...filter, query: event.target.value })}
      />
    </div>
  );
}

function IpChips({ label, ips }: { label: string; ips: readonly string[] }) {
  if (ips.length === 0) return null;
  const rest = ips.slice(CHIPS_SHOWN);
  return (
    <div className="b89Allow__ipRow">
      <span className="b89Allow__ipLabel">{label}</span>
      {ips.slice(0, CHIPS_SHOWN).map((ip) => (
        <code key={ip} className="b89Allow__ip">
          {ip}
        </code>
      ))}
      {rest.length > 0 && (
        <EuiToolTip content={rest.join(', ')}>
          <span className="b89Allow__more" tabIndex={0} aria-label={`${rest.length} IPs más: ${rest.join(', ')}`}>
            +{rest.length}
          </span>
        </EuiToolTip>
      )}
    </div>
  );
}

export function StatusBadge({ status }: { status: AllowlistStatus }) {
  return <EuiBadge color={STATUS_COLOR[status]}>{STATUS_LABEL[status]}</EuiBadge>;
}

export function AllowlistTable({
  entries,
  canManage,
  onEdit,
}: {
  entries: readonly AllowlistEntry[];
  canManage: boolean;
  onEdit: (entry: AllowlistEntry, trigger: HTMLElement | null) => void;
}) {
  const columns: EuiBasicTableColumn<AllowlistEntry>[] = [
    {
      field: 'name',
      name: 'Nombre',
      width: '28%',
      render: (name: string, entry: AllowlistEntry) => {
        const reason = reviewReason(entry);
        return (
          <div>
            <strong>{name}</strong>
            <div className="b89Allow__sub">
              {[KIND_LABEL[entry.kind], entry.product, entry.country].filter(Boolean).join(' · ')}
            </div>
            {reason && (
              <div className="b89Allow__rowWarning">
                <span aria-hidden="true">⚠ </span>
                {reason}
              </div>
            )}
          </div>
        );
      },
    },
    {
      field: 'status',
      name: 'Estado',
      width: '24%',
      render: (status: AllowlistStatus) => (
        <div>
          <StatusBadge status={status} />
          <div className="b89Allow__sub">{STATUS_EFFECT[status]}</div>
        </div>
      ),
    },
    {
      field: 'prodIps',
      name: 'IPs',
      render: (_: unknown, entry: AllowlistEntry) =>
        entry.prodIps.length + entry.sandboxIps.length === 0 ? (
          <span className="b89Allow__sub">Sin IPs</span>
        ) : (
          <div>
            <IpChips label="Prod" ips={entry.prodIps} />
            <IpChips label="Sandbox" ips={entry.sandboxIps} />
          </div>
        ),
    },
    {
      field: 'markers',
      name: 'Identificadores',
      width: '12%',
      render: (markers: readonly string[]) =>
        markers.length === 0 ? (
          <span className="b89Allow__sub">Ninguno</span>
        ) : (
          <EuiToolTip content={markers.join(', ')}>
            <span tabIndex={0} aria-label={`Identificadores: ${markers.join(', ')}`}>
              {markers.length}
            </span>
          </EuiToolTip>
        ),
    },
  ];
  if (canManage) {
    columns.push({
      field: 'id',
      name: 'Acciones',
      width: '96px',
      render: (_: string, entry: AllowlistEntry) => (
        <EuiButtonEmpty
          size="xs"
          iconType="pencil"
          aria-label={`Editar ${entry.name}`}
          onClick={(event: React.MouseEvent<HTMLButtonElement>) => onEdit(entry, event.currentTarget)}
        >
          Editar
        </EuiButtonEmpty>
      ),
    });
  }
  return (
    <EuiBasicTable<AllowlistEntry>
      className="b89Allow__table"
      items={[...entries]}
      itemId="id"
      columns={columns}
      tableLayout="auto"
      data-test-subj="b89AllowTable"
    />
  );
}

/** Aparece solo con cambios sin guardar y dice exactamente qué cambiará. */
export function AllowlistSaveBar({
  changes,
  saving,
  conflict,
  stepUp,
  validation,
  logoutHref,
  onSave,
  onDiscard,
  onReload,
}: {
  changes: readonly AllowlistChange[];
  saving: boolean;
  conflict: boolean;
  stepUp: boolean;
  validation: string | null;
  logoutHref: string;
  onSave: () => void;
  onDiscard: () => void;
  onReload: () => void;
}) {
  if (changes.length === 0 && !conflict) return null;
  const lines = changes.map(describeChange);
  return (
    <div className="b89Allow__saveBar" role="region" aria-label="Cambios sin guardar en la lista blanca">
      {conflict ? (
        <EuiCallOut color="warning" size="s" iconType="alert" title="Alguien guardó la lista blanca mientras editabas">
          <p>Para seguir, carga la versión guardada. Tus cambios sin guardar se pierden.</p>
          <EuiButton size="s" onClick={onReload}>
            Cargar la versión guardada
          </EuiButton>
        </EuiCallOut>
      ) : (
        <>
          <div>
            <strong>
              {changes.length === 1 ? '1 cambio sin guardar' : `${changes.length} cambios sin guardar`}
            </strong>
            <ul className="b89Allow__diff">
              {lines.slice(0, CHANGES_SHOWN).map((line) => (
                <li key={line}>{line}</li>
              ))}
              {lines.length > CHANGES_SHOWN && <li>y {lines.length - CHANGES_SHOWN} más</li>}
            </ul>
          </div>
          <div className="b89Allow__inlineActions">
            <EuiButton fill size="s" onClick={onSave} isLoading={saving} data-test-subj="b89AllowSave">
              Guardar lista blanca
            </EuiButton>
            <EuiButtonEmpty size="s" onClick={onDiscard} disabled={saving}>
              Descartar
            </EuiButtonEmpty>
          </div>
        </>
      )}
      {validation && (
        <EuiCallOut color="danger" size="s" iconType="alert" title="No se guardó: hay datos no válidos" role="alert">
          <p>{validation}</p>
        </EuiCallOut>
      )}
      {stepUp && (
        <EuiCallOut color="warning" size="s" iconType="lock" title="Para guardar, vuelve a iniciar sesión">
          <p>Por seguridad, guardar la lista blanca pide un inicio de sesión reciente. Tus cambios se pierden al salir.</p>
          <EuiButton size="s" href={logoutHref}>
            Cerrar sesión y volver a entrar
          </EuiButton>
        </EuiCallOut>
      )}
    </div>
  );
}

function IpField({
  id,
  label,
  value,
  parsed,
  error,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  parsed: { ips: string[]; invalid: string[] };
  error?: string;
  onChange: (value: string) => void;
}) {
  return (
    <EuiFormRow
      label={label}
      fullWidth
      isInvalid={Boolean(error)}
      error={error}
      helpText={
        <span aria-live="polite">
          Pega desde Excel: separa con comas, espacios o saltos de línea. <strong>{parsed.ips.length === 1 ? '1 IP válida' : `${parsed.ips.length} IPs válidas`}</strong>
          {parsed.invalid.length > 0 && (
            <span className="b89Allow__invalid">
              {' '}
              · No son IP y se anotarán en la nota como «por reconfirmar»: {parsed.invalid.join(', ')}
            </span>
          )}
        </span>
      }
    >
      <EuiTextArea
        id={id}
        fullWidth
        rows={3}
        className="b89Allow__mono"
        value={value}
        isInvalid={Boolean(error)}
        onChange={(event) => onChange(event.target.value)}
      />
    </EuiFormRow>
  );
}

/** Campos del formulario de una entrada (el flyout los envuelve). */
export function EntryFormFields({
  form,
  check,
  showErrors,
  onChange,
}: {
  form: EntryForm;
  check: FormCheck;
  /** Los errores aparecen después del primer intento de aplicar o al salir del campo. */
  showErrors: boolean;
  onChange: (next: EntryForm) => void;
}) {
  const set = <K extends keyof EntryForm>(key: K, value: EntryForm[K]) => onChange({ ...form, [key]: value });
  const error = (field: keyof FormCheck['errors']) => (showErrors ? check.errors[field] : undefined);
  const text = (key: 'name' | 'product' | 'country' | 'company', label: string, help?: string) => (
    <EuiFormRow label={label} fullWidth isInvalid={Boolean(error(key))} error={error(key)} helpText={help}>
      <EuiFieldText
        id={`b89-allow-${key}`}
        fullWidth
        value={form[key]}
        isInvalid={Boolean(error(key))}
        onChange={(event) => set(key, event.target.value)}
      />
    </EuiFormRow>
  );
  return (
    <div className="b89Allow__form">
      {text('name', 'Nombre (obligatorio)')}
      <EuiFormRow label="Tipo" fullWidth>
        <EuiSelect
          id="b89-allow-kind"
          fullWidth
          options={ALLOWLIST_KINDS.map((kind) => ({ value: kind, text: KIND_LABEL[kind] }))}
          value={form.kind}
          onChange={(event) => set('kind', event.target.value as EntryForm['kind'])}
        />
      </EuiFormRow>
      {text('product', 'Producto', 'P. ej. Payouts, Payins.')}
      {text('country', 'País')}
      {text('company', 'Empresa')}
      <EuiFormRow label="Estado" fullWidth helpText={STATUS_EFFECT[form.status]}>
        <EuiSelect
          id="b89-allow-status"
          fullWidth
          options={ALLOWLIST_STATUSES.map((status) => ({ value: status, text: STATUS_LABEL[status] }))}
          value={form.status}
          onChange={(event) => set('status', event.target.value as EntryForm['status'])}
        />
      </EuiFormRow>
      <IpField
        id="b89-allow-prod"
        label="IPs de producción"
        value={form.prodText}
        parsed={check.prod}
        error={error('prodText')}
        onChange={(value) => set('prodText', value)}
      />
      <IpField
        id="b89-allow-sandbox"
        label="IPs de sandbox"
        value={form.sandboxText}
        parsed={check.sandbox}
        error={error('sandboxText')}
        onChange={(value) => set('sandboxText', value)}
      />
      <EuiFormRow
        label="Identificadores (opcional)"
        fullWidth
        isInvalid={Boolean(check.errors.markersText)}
        error={check.errors.markersText}
        helpText="Textos que aparecen en sus peticiones, como su código de comercio en la URL. Sirven para reconocerlo aunque llame desde una IP desconocida. Sepáralos con comas."
      >
        <EuiTextArea
          id="b89-allow-markers"
          fullWidth
          rows={2}
          className="b89Allow__mono"
          value={form.markersText}
          isInvalid={Boolean(check.errors.markersText)}
          onChange={(event) => set('markersText', event.target.value)}
        />
      </EuiFormRow>
      <EuiFormRow label="Nota" fullWidth isInvalid={Boolean(error('note'))} error={error('note')}>
        <EuiTextArea
          id="b89-allow-note"
          fullWidth
          rows={2}
          value={form.note}
          isInvalid={Boolean(error('note'))}
          onChange={(event) => set('note', event.target.value)}
        />
      </EuiFormRow>
      {check.warnings.map((warning) => (
        <p key={warning} className="b89Allow__warning" role="note">
          <span aria-hidden="true">⚠ </span>
          {warning}
        </p>
      ))}
    </div>
  );
}

// ======================================================================== flyout

function EntryFlyout({
  entry,
  onApply,
  onDelete,
  onClose,
}: {
  /** null: entrada nueva. */
  entry: AllowlistEntry | null;
  onApply: (form: EntryForm) => void;
  onDelete: () => void;
  onClose: () => void;
}) {
  const [form, setForm] = useState<EntryForm>(() => (entry ? formFromEntry(entry) : EMPTY_FORM));
  const [showErrors, setShowErrors] = useState(false);
  const check = useMemo(() => checkForm(form), [form]);
  const title = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    // Después de que el flyout toma el foco: el lector de pantalla anuncia el título primero.
    const timer = setTimeout(() => title.current?.focus(), 50);
    return () => clearTimeout(timer);
  }, []);
  const apply = () => {
    setShowErrors(true);
    if (formIsValid(check)) onApply(form);
  };
  return (
    <EuiFlyout ownFocus onClose={onClose} size="m" aria-labelledby="b89-allow-flyout-title" className="b89Allow__flyout">
      <EuiFlyoutHeader hasBorder>
        <EuiTitle size="s">
          <h2 id="b89-allow-flyout-title" ref={title} tabIndex={-1}>
            {entry ? `Editar ${entry.name}` : 'Agregar cliente o proveedor'}
          </h2>
        </EuiTitle>
      </EuiFlyoutHeader>
      <EuiFlyoutBody>
        <div lang="es-PE" translate="no">
          <EntryFormFields form={form} check={check} showErrors={showErrors} onChange={setForm} />
        </div>
      </EuiFlyoutBody>
      <EuiFlyoutFooter>
        <div className="b89Allow__flyoutFooter" lang="es-PE" translate="no">
          <div className="b89Allow__inlineActions">
            <EuiButton fill size="s" onClick={apply}>
              {entry ? 'Aplicar cambios' : 'Agregar a la lista'}
            </EuiButton>
            <EuiButtonEmpty size="s" onClick={onClose}>
              Cancelar
            </EuiButtonEmpty>
            {entry && (
              <EuiButtonEmpty size="s" color="danger" iconType="trash" onClick={onDelete}>
                Quitar de la lista
              </EuiButtonEmpty>
            )}
          </div>
          <p className="b89Allow__sub">Se aplica al pulsar «Guardar lista blanca».</p>
          {showErrors && !formIsValid(check) && (
            <p className="b89Allow__invalid" role="alert">
              Corrige los campos marcados.
            </p>
          )}
        </div>
      </EuiFlyoutFooter>
    </EuiFlyout>
  );
}

// ======================================================================== panel

type Editing = { readonly entry: AllowlistEntry | null } | null;

export function CloudflareAllowlistPanel() {
  const { api, can, notifications, basePath } = useConsole();
  const canRead = can(CAPABILITIES.allowlistRead);
  const [data, setData] = useState<AllowlistResponse | null>(null);
  const [loadError, setLoadError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [draft, setDraft] = useState<readonly AllowlistEntry[] | null>(null);
  const [filter, setFilter] = useState<AllowlistFilter>(DEFAULT_FILTER);
  const [ipText, setIpText] = useState('');
  const [editing, setEditing] = useState<Editing>(null);
  const [deleting, setDeleting] = useState<AllowlistEntry | null>(null);
  const [saving, setSaving] = useState(false);
  const [conflict, setConflict] = useState(false);
  const [stepUp, setStepUp] = useState(false);
  const [validation, setValidation] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<unknown>(null);
  const trigger = useRef<HTMLElement | null>(null);
  const mounted = useRef(true);
  useEffect(
    () => () => {
      mounted.current = false;
    },
    [],
  );

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const response = await api.get<AllowlistResponse>(PATH);
      if (mounted.current) setData(response);
    } catch (error) {
      if (mounted.current) setLoadError(error);
    } finally {
      if (mounted.current) setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    if (canRead) void load();
  }, [canRead, load]);

  const saved = data?.entries ?? [];
  const entries = draft ?? saved;
  const changes = useMemo(() => (draft ? diffAllowlist(saved, draft) : []), [saved, draft]);
  const dirty = changes.length > 0;
  const canManage = Boolean(data?.canManage) && can(CAPABILITIES.allowlistManage);
  const visible = useMemo(() => filterEntries(entries, filter), [entries, filter]);
  const lookup = useMemo(() => lookupIp(entries, ipText), [entries, ipText]);

  useEffect(() => {
    if (!dirty) return undefined;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
      event.returnValue = '';
    };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty]);

  if (!canRead) return <AllowlistNoAccess />;

  const openEditor = (entry: AllowlistEntry | null, from: HTMLElement | null) => {
    trigger.current = from ?? (typeof document === 'undefined' ? null : (document.activeElement as HTMLElement | null));
    setEditing({ entry });
  };
  const closeEditor = () => {
    setEditing(null);
    setDeleting(null);
    const back = trigger.current;
    // Si la fila ya no existe (se quitó), el foco vuelve al botón «Agregar».
    setTimeout(() => {
      if (back && back.isConnected) back.focus();
      else document.querySelector<HTMLElement>('[data-test-subj="b89AllowAdd"]')?.focus();
    }, 0);
  };

  const resetSaveState = () => {
    setValidation(null);
    setStepUp(false);
    setSaveError(null);
  };

  const apply = (form: EntryForm) => {
    const current = editing?.entry ?? null;
    const id = current ? current.id : entryId(form, new Set(entries.map((entry) => entry.id)));
    setDraft(upsertEntry(entries, entryFromForm(form, id)));
    resetSaveState();
    closeEditor();
  };

  const confirmDelete = () => {
    if (!deleting) return;
    setDraft(removeEntry(entries, deleting.id));
    resetSaveState();
    closeEditor();
  };

  const save = async () => {
    if (!data || !draft) return;
    resetSaveState();
    setSaving(true);
    try {
      const response = await api.put<AllowlistResponse>(PATH, { expectedRevision: data.revision, entries: draft });
      if (!mounted.current) return;
      setData(response);
      setDraft(null);
      notifications.toasts.addSuccess({
        title: `Lista blanca guardada (revisión ${response.revision}). El colector la aplica en menos de 5 minutos.`,
      });
    } catch (error) {
      if (!mounted.current) return;
      if (error instanceof B89ApiError && error.code === 'STATE_CONFLICT') setConflict(true);
      else if (error instanceof B89ApiError && error.code === 'STEP_UP_REQUIRED') setStepUp(true);
      else if (error instanceof B89ApiError && error.code === 'VALIDATION_FAILED') setValidation(validationMessage(error.fields, draft));
      else setSaveError(error);
    } finally {
      if (mounted.current) setSaving(false);
    }
  };

  const reloadAfterConflict = () => {
    setDraft(null);
    setConflict(false);
    resetSaveState();
    void load();
  };

  const discard = () => {
    setDraft(null);
    resetSaveState();
  };

  return (
    <section className="b89Allow" lang="es-PE" translate="no" aria-label="Lista blanca de la API de pagos">
      {loading && !data ? (
        <EuiLoadingContent lines={6} />
      ) : !data ? (
        <div>
          <ErrorCallout error={loadError} onRetry={() => void load()} />
          <p className="b89Allow__sub">
            Si sigue fallando, la API de B89 puede estar caída: revisa «Salud de fuentes» o avisa al equipo de plataforma.
          </p>
        </div>
      ) : (
        <>
          {loadError !== null && (
            <EuiCallOut color="warning" size="s" iconType="alert" title="No se pudo actualizar: se muestran los últimos datos recibidos">
              <EuiButtonEmpty size="xs" flush="left" onClick={() => void load()}>
                Reintentar
              </EuiButtonEmpty>
            </EuiCallOut>
          )}
          <AllowlistAnswerLine
            entries={entries}
            revision={data.revision}
            updatedAt={data.updatedAt}
            canManage={canManage}
            onAdd={() => openEditor(null, null)}
            onReview={() => setFilter({ ...DEFAULT_FILTER, status: 'review' })}
          />
          <AllowlistRule />
          <div className="b89Allow__lookup">
            <EuiFormRow label="¿Esta IP es de alguien?" helpText="Escribe una IP para ver de quién es.">
              <EuiFieldText
                id="b89-allow-lookup"
                compressed
                icon="search"
                placeholder="34.199.50.40"
                className="b89Allow__mono"
                value={ipText}
                onChange={(event) => setIpText(event.target.value)}
              />
            </EuiFormRow>
            <div aria-live="polite">
              <IpLookupResult lookup={lookup} />
            </div>
          </div>
          {saved.length === 0 && entries.length === 0 ? (
            <p className="b89Allow__empty">
              La lista blanca está vacía.{' '}
              {canManage ? 'Agrega el primer cliente o proveedor con sus IPs.' : 'Pide a un administrador que la cargue.'}
            </p>
          ) : (
            <>
              <AllowlistFilters entries={entries} filter={filter} onChange={setFilter} />
              {visible.length === 0 ? (
                <p className="b89Allow__empty">
                  Ninguna entrada coincide con los filtros.{' '}
                  <EuiButtonEmpty size="xs" flush="left" onClick={() => setFilter(DEFAULT_FILTER)}>
                    Quitar filtros
                  </EuiButtonEmpty>
                </p>
              ) : (
                <AllowlistTable entries={visible} canManage={canManage} onEdit={(entry, from) => openEditor(entry, from)} />
              )}
            </>
          )}
          {saveError !== null && <ErrorCallout error={saveError} onRetry={() => void save()} />}
          {canManage && (
            <AllowlistSaveBar
              changes={changes}
              saving={saving}
              conflict={conflict}
              stepUp={stepUp}
              validation={validation}
              logoutHref={`${basePath}${LOGOUT_PATH}`}
              onSave={() => void save()}
              onDiscard={discard}
              onReload={reloadAfterConflict}
            />
          )}
        </>
      )}
      {editing && (
        <EntryFlyout
          entry={editing.entry}
          onApply={apply}
          onDelete={() => editing.entry && setDeleting(editing.entry)}
          onClose={closeEditor}
        />
      )}
      {deleting && (
        <EuiConfirmModal
          title={`¿Quitar ${deleting.name} de la lista blanca?`}
          onCancel={() => setDeleting(null)}
          onConfirm={confirmDelete}
          cancelButtonText="Cancelar"
          confirmButtonText="Quitar"
          buttonColor="danger"
          defaultFocusedButton="cancel"
        >
          <p lang="es-PE" translate="no">
            Se quita del borrador; el cambio se aplica al pulsar «Guardar lista blanca».
          </p>
        </EuiConfirmModal>
      )}
    </section>
  );
}
