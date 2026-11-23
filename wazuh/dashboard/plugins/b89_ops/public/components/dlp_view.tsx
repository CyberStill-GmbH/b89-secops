/*
 * Copyright B89. SPDX-License-Identifier: Apache-2.0
 */

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  EuiBadge,
  EuiButton,
  EuiButtonEmpty,
  EuiCallOut,
  EuiCheckbox,
  EuiConfirmModal,
  EuiFormRow,
  EuiLoadingContent,
  EuiSpacer,
  EuiTextArea,
} from '@elastic/eui';
import { B89ApiError } from '../api/client';
import {
  createDlpEnrollmentToken,
  type DlpEndpoint,
  type DlpPolicy,
  getDlpEndpoints,
  getDlpPolicy,
  revokeDlpEndpoint,
  saveDlpPolicy,
} from '../api/dlp';
import { B89Page, useConsole } from './console_context';
import { ErrorCallout, Mono, Timestamp } from './primitives';

const RULES = [
  {
    id: 'B89_CRED_PRIVATE_KEY_PEM',
    title: 'Claves privadas',
    detail: 'Archivos PEM RSA, EC, OpenSSH, DSA y formato genérico.',
  },
  {
    id: 'B89_CRED_GITHUB_TOKEN',
    title: 'Accesos a GitHub',
    detail: 'Tokens clásicos y de grano fino con formato reconocible.',
  },
  {
    id: 'B89_CRED_SLACK_TOKEN',
    title: 'Accesos a Slack',
    detail: 'Tokens con prefijo y longitud compatibles con Slack.',
  },
  {
    id: 'B89_CRED_GOOGLE_API_KEY',
    title: 'Claves de Google API',
    detail: 'Claves con el prefijo de API de Google.',
  },
  {
    id: 'B89_CRED_AZURE_STORAGE_KEY',
    title: 'Claves de Azure Storage',
    detail: 'Valores AccountKey de cadenas de conexión reconocibles.',
  },
  {
    id: 'B89_CRED_OPENAI_API_KEY',
    title: 'Claves API de OpenAI',
    detail: 'Formatos de clave con prefijos reconocibles.',
  },
  {
    id: 'B89_CRED_AWS_ACCESS_KEY_PAIR',
    title: 'Par de acceso AWS',
    detail: 'Identificador y clave secreta encontrados juntos en el mismo archivo.',
    advanced: true,
  },
  {
    id: 'B89_SECRET_DATABASE_CONNECTION',
    title: 'Credenciales de bases de datos',
    detail: 'Cadenas de conexión con usuario y contraseña en formatos reconocibles.',
    advanced: true,
  },
  {
    id: 'B89_SECRET_CREDENTIAL_ASSIGNMENT',
    title: 'Contraseñas asignadas en texto',
    detail: 'Campos password, client_secret o api_key con un valor visible.',
    advanced: true,
  },
  {
    id: 'B89_PII_PERU_DNI_CONTEXTUAL',
    title: 'DNI peruano con contexto',
    detail: 'Ocho dígitos cerca de una etiqueta DNI o documento de identidad.',
    advanced: true,
  },
  {
    id: 'B89_PII_PERU_RUC_CONTEXTUAL',
    title: 'RUC peruano con contexto',
    detail: 'Once dígitos cerca de una etiqueta RUC o registro tributario.',
    advanced: true,
  },
] as const;
const HASH = /^[0-9a-f]{64}$/iu;

function parseFingerprints(text: string): { values: string[]; invalid: string[] } {
  const values: string[] = [];
  const invalid: string[] = [];
  const seen = new Set<string>();
  for (const [index, source] of text.split(/\r?\n/u).entries()) {
    const line = source.trim();
    if (!line || line.startsWith('#')) continue;
    if (!HASH.test(line)) {
      invalid.push(String(index + 1));
      continue;
    }
    const normalized = line.toLowerCase();
    if (!seen.has(normalized)) {
      seen.add(normalized);
      values.push(normalized);
    }
  }
  return { values, invalid };
}

function nextVersion(value: string): string {
  const match = /^(\d+)\.(\d+)\.(\d+)$/u.exec(value);
  if (!match) return '1.0.0';
  return `${match[1]}.${Number(match[2]) + 1}.0`;
}

function endpointState(endpoint: DlpEndpoint): 'applied' | 'pending' | 'unknown' | 'revoked' {
  if (endpoint.status === 'revoked') return 'revoked';
  if (endpoint.status === 're-enrollment-required') return 'pending';
  if (endpoint.status === 'offline') return 'unknown';
  if (endpoint.status === 'updating') return 'pending';
  return 'applied';
}

export function DlpView() {
  const { api, can } = useConsole();
  const [policy, setPolicy] = useState<DlpPolicy | null>(null);
  const [endpoints, setEndpoints] = useState<readonly DlpEndpoint[]>([]);
  const [policyError, setPolicyError] = useState<unknown>(null);
  const [endpointError, setEndpointError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [draftRules, setDraftRules] = useState<string[]>([]);
  const [draftHashes, setDraftHashes] = useState('');
  const [hashError, setHashError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [conflict, setConflict] = useState(false);
  const [enrollmentBusy, setEnrollmentBusy] = useState(false);
  const [enrollmentToken, setEnrollmentToken] = useState<string | null>(null);
  const [enrollmentExpires, setEnrollmentExpires] = useState<string | null>(null);
  const [stepUpRequired, setStepUpRequired] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<DlpEndpoint | null>(null);
  const [revoking, setRevoking] = useState(false);

  const loadPolicy = useCallback(async () => {
    setPolicyError(null);
    try {
      const data = await getDlpPolicy(api);
      setPolicy(data);
      setDraftRules([...data.enabledRuleIds]);
      setDraftHashes(data.fingerprintsSha256.join('\n'));
      setConflict(false);
    } catch (error) {
      setPolicyError(error);
    } finally {
      setLoading(false);
    }
  }, [api]);

  const loadEndpoints = useCallback(async () => {
    setEndpointError(null);
    try {
      const result = await getDlpEndpoints(api);
      setEndpoints(result.items);
    } catch (error) {
      setEndpointError(error);
    }
  }, [api]);

  useEffect(() => {
    void loadPolicy();
    void loadEndpoints();
    const timer = window.setInterval(() => void loadEndpoints(), 5000);
    return () => window.clearInterval(timer);
  }, [loadPolicy, loadEndpoints]);

  const parsedFingerprints = useMemo(() => parseFingerprints(draftHashes), [draftHashes]);
  const canRead = can('dlp.read');
  const canConfigure = can('dlp.configure');
  const activeEndpoints = endpoints.filter((endpoint) => ['current', 'updating'].includes(endpoint.status)).length;
  const pendingEndpoints = policy
    ? endpoints.filter((endpoint) => endpointState(endpoint) === 'pending').length
    : 0;

  const save = async () => {
    if (!policy) return;
    if (parsedFingerprints.invalid.length > 0) {
      setHashError(`Revisa las líneas ${parsedFingerprints.invalid.slice(0, 8).join(', ')}: cada una debe tener 64 caracteres hexadecimales.`);
      return;
    }
    if (draftRules.length === 0 && parsedFingerprints.values.length === 0) {
      setHashError('Activa al menos una regla o agrega una huella para proteger los equipos.');
      return;
    }
    setSaving(true);
    setNotice(null);
    setHashError(null);
    setConflict(false);
    setStepUpRequired(false);
    try {
      const updated = await saveDlpPolicy(api, {
        expectedRevision: policy.revision,
        policyVersion: nextVersion(policy.policyVersion),
        enabledRuleIds: draftRules,
        fingerprintsSha256: parsedFingerprints.values,
      });
      setPolicy(updated);
      setDraftRules([...updated.enabledRuleIds]);
      setDraftHashes(updated.fingerprintsSha256.join('\n'));
      setNotice(`Política ${updated.policyVersion} guardada. Los equipos conectados la recibirán en su siguiente consulta.`);
      await loadEndpoints();
    } catch (error) {
      if (error instanceof B89ApiError && error.code === 'STATE_CONFLICT') {
        setConflict(true);
        setNotice('Otra persona guardó cambios primero. Recarga la política antes de volver a guardar.');
      } else if (error instanceof B89ApiError && error.code === 'STEP_UP_REQUIRED') {
        setStepUpRequired(true);
        setNotice(null);
      } else {
        setPolicyError(error);
      }
    } finally {
      setSaving(false);
    }
  };

  const createToken = async () => {
    setEnrollmentBusy(true);
    setEnrollmentToken(null);
    setEnrollmentExpires(null);
    setStepUpRequired(false);
    try {
      const result = await createDlpEnrollmentToken(api);
      setEnrollmentToken(result.token);
      setEnrollmentExpires(result.expiresAt);
    } catch (error) {
      if (error instanceof B89ApiError && error.code === 'STEP_UP_REQUIRED') {
        setStepUpRequired(true);
      } else {
        setPolicyError(error);
      }
    } finally {
      setEnrollmentBusy(false);
    }
  };

  const revokeEndpoint = async () => {
    if (!revokeTarget) return;
    setRevoking(true);
    setStepUpRequired(false);
    try {
      await revokeDlpEndpoint(api, revokeTarget.id);
      setRevokeTarget(null);
      setNotice(`Se revocó la credencial de ${revokeTarget.hostname}. El agente dejará de recibir políticas nuevas.`);
      await loadEndpoints();
    } catch (error) {
      if (error instanceof B89ApiError && error.code === 'STEP_UP_REQUIRED') {
        setStepUpRequired(true);
        setRevokeTarget(null);
      } else {
        setPolicyError(error);
      }
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
      setDraftHashes((previous) => [previous.trim(), text.trim()].filter(Boolean).join('\n'));
      setHashError(null);
    };
    reader.onerror = () => setHashError('No se pudo leer el archivo. Usa un .txt UTF-8 con un SHA-256 por línea.');
    reader.readAsText(file);
  };

  if (!canRead) {
    return (
      <B89Page
        title="DLP de endpoints"
        description="Administra reglas de credenciales y fingerprints de archivos sensibles."
      >
        <EuiCallOut color="warning" title="Tu rol no tiene acceso a DLP">
          Pide al administrador que te asigne el acceso DLP correspondiente.
        </EuiCallOut>
      </B89Page>
    );
  }

  return (
    <B89Page
      title="DLP de endpoints"
      description={canConfigure
        ? "Define qué credenciales y huellas SHA-256 detecta Ferrispector en las carpetas aprobadas de cada equipo."
        : "Consulta qué protege Ferrispector y si los equipos están aplicando la política vigente."}
      actions={<EuiBadge color={pendingEndpoints > 0 ? 'warning' : 'hollow'}>{pendingEndpoints > 0 ? `${pendingEndpoints} equipos pendientes` : `${activeEndpoints} equipos conectados`}</EuiBadge>}
    >
      {policyError && <ErrorCallout error={policyError} onRetry={() => { void loadPolicy(); void loadEndpoints(); }} />}
      {!canConfigure && <EuiCallOut color="primary" title="Vista de consulta para investigación"><p>Puedes revisar las reglas activas, las huellas SHA-256 y el estado de los equipos. Para cambiar la política o administrar equipos, contacta al Administrador.</p></EuiCallOut>}
      {stepUpRequired && (
        <EuiCallOut color="warning" title="Confirma tu sesión de nuevo">
          Reautentícate para guardar cambios, crear una clave de instalación o revocar un equipo. Después vuelve a intentar la acción.
        </EuiCallOut>
      )}
      {notice && (
        <EuiCallOut color={conflict ? 'warning' : 'success'} title={conflict ? 'Hay cambios más recientes' : 'Cambios guardados'}>
          <p>{notice}</p>
          {conflict && <EuiButtonEmpty size="xs" flush="left" onClick={() => void loadPolicy()}>Recargar la política</EuiButtonEmpty>}
        </EuiCallOut>
      )}
      {loading && !policy ? <EuiLoadingContent lines={5} /> : policy && (
        <>
          <section className="b89Panel" aria-labelledby="b89-dlp-rules">
            <div className="b89Panel__header">
              <h2 id="b89-dlp-rules">Reglas de detección</h2>
              <span className="b89Panel__meta">Versión {policy.policyVersion} · revisión {policy.revision}</span>
            </div>
            <p className="b89Dlp__intro">Activa los tipos de credencial que debe revisar el agente. El hallazgo genera una alerta; no bloquea el archivo.</p>
            <div className="b89Dlp__rules">
              <h3>Reglas principales</h3>
              {RULES.filter((rule) => !('advanced' in rule && rule.advanced)).map((rule) => (
                <div className="b89Dlp__rule" key={rule.id}>
                  <EuiCheckbox
                    id={`dlp-rule-${rule.id}`}
                    checked={draftRules.includes(rule.id)}
                    disabled={!canConfigure}
                    onChange={(event) => setDraftRules((current) => event.target.checked ? [...current, rule.id] : current.filter((id) => id !== rule.id))}
                    label={rule.title}
                  />
                  <span className="b89Dlp__ruleDetail">{rule.detail}</span>
                  <Mono>{rule.id}</Mono>
                </div>
              ))}
              <h3>Reglas avanzadas</h3>
              <p className="b89Dlp__note">Pueden detectar información personal o valores escritos en texto. Actívalas solo en carpetas aprobadas: elevan el riesgo de falsos positivos.</p>
              {RULES.filter((rule) => 'advanced' in rule && rule.advanced).map((rule) => (
                <div className="b89Dlp__rule b89Dlp__rule--advanced" key={rule.id}>
                  <EuiCheckbox
                    id={`dlp-rule-${rule.id}`}
                    checked={draftRules.includes(rule.id)}
                    disabled={!canConfigure}
                    onChange={(event) => setDraftRules((current) => event.target.checked ? [...current, rule.id] : current.filter((id) => id !== rule.id))}
                    label={rule.title}
                  />
                  <span className="b89Dlp__ruleDetail">{rule.detail}</span>
                  <Mono>{rule.id}</Mono>
                </div>
              ))}
            </div>
          </section>

          <section className="b89Panel" aria-labelledby="b89-dlp-fingerprints">
            <div className="b89Panel__header">
              <h2 id="b89-dlp-fingerprints">Fingerprints de documentos</h2>
              <span className="b89Panel__meta">{parsedFingerprints.values.length} SHA-256</span>
            </div>
            <p className="b89Dlp__intro">Agrega un hash SHA-256 por línea. Una coincidencia exacta genera una alerta; el nombre y el contenido del documento no se envían.</p>
            <EuiFormRow label="Importar catálogo .txt" helpText="Solo hashes SHA-256 de 64 caracteres hexadecimales; las líneas que empiezan con # se ignoran.">
              <input className="b89Dlp__file" type="file" accept=".txt,text/plain" aria-label="Importar catálogo de fingerprints SHA-256" onChange={importFile} disabled={!canConfigure} />
            </EuiFormRow>
            <EuiSpacer size="s" />
            <EuiFormRow label="Fingerprints SHA-256" isInvalid={Boolean(hashError)} error={hashError ?? undefined}>
              <EuiTextArea
                aria-label="Fingerprints SHA-256, uno por línea"
                value={draftHashes}
                readOnly={!canConfigure}
                onChange={(event) => { setDraftHashes(event.target.value); setHashError(null); }}
                rows={8}
                resize="vertical"
                placeholder="Pega aquí un SHA-256 por línea"
              />
            </EuiFormRow>
            {parsedFingerprints.invalid.length > 0 && <p className="b89Dlp__validation">{parsedFingerprints.invalid.length} líneas no tienen formato SHA-256.</p>}
          </section>

          <div className="b89Dlp__actions">
            {canConfigure && <>
              <EuiButton fill onClick={() => void save()} isLoading={saving} disabled={saving || conflict || !policy}>
                Guardar y distribuir
              </EuiButton>
              <EuiButtonEmpty onClick={() => void loadPolicy()} disabled={saving}>Descartar cambios</EuiButtonEmpty>
            </>}
            <span className="b89Dlp__version">Último cambio: <Timestamp iso={policy.updatedAt} /></span>
          </div>
          <p className="b89Dlp__note">Los equipos aplican la nueva revisión al consultar al servidor. La tabla confirma la revisión cuando cada agente responde; guardar aquí no significa que todos ya la recibieron.</p>

          <section className="b89Panel" aria-labelledby="b89-dlp-endpoints">
            <div className="b89Panel__header">
              <h2 id="b89-dlp-endpoints">Equipos y distribución</h2>
              <span className="b89Panel__meta">Actualizado automáticamente cada 5 segundos</span>
            </div>
            {endpointError ? (
              <ErrorCallOutCompact error={endpointError} retry={() => void loadEndpoints()} />
            ) : endpoints.length === 0 ? (
              <p className="b89Panel__empty">Todavía no hay equipos registrados. Crea una clave de instalación, instala Ferrispector en la otra PC con esa clave y aparecerá aquí automáticamente.</p>
            ) : (
              <div className="b89TableScroll">
                <table className="b89Dlp__table">
                  <thead><tr><th scope="col">Equipo</th><th scope="col">Estado</th><th scope="col">Último contacto</th><th scope="col">Revisión aplicada</th><th scope="col">Acceso</th></tr></thead>
                  <tbody>{endpoints.map((endpoint) => {
                    const state = endpointState(endpoint);
                    return <tr key={endpoint.id}>
                      <th scope="row">{endpoint.hostname}{endpoint.agentId && <small>Agente Wazuh {endpoint.agentId}</small>}</th>
                      <td><EuiBadge color={state === 'applied' ? 'success' : state === 'pending' ? 'warning' : 'hollow'}>{state === 'applied' ? 'Al día' : state === 'pending' ? endpoint.status === 're-enrollment-required' ? 'Reinscripción necesaria' : 'Aplicando' : state === 'revoked' ? 'Revocado' : 'Sin conexión'}</EuiBadge></td>
                      <td><Timestamp iso={endpoint.lastSeenAt} /></td>
                      <td>{endpoint.currentRevision === null ? 'Sin confirmar' : `Revisión ${endpoint.currentRevision} · ${endpoint.currentPolicyVersion ?? 'sin versión'}`}</td>
                      <td>{canConfigure && endpoint.status !== 'offline' && endpoint.status !== 'revoked' && <EuiButtonEmpty size="xs" color="danger" onClick={() => setRevokeTarget(endpoint)}>Revocar credencial</EuiButtonEmpty>}{endpoint.status === 'revoked' && endpoint.revokedAt && <span>Revocada <Timestamp iso={endpoint.revokedAt} /></span>}{!canConfigure && endpoint.status !== 'revoked' && <span>Administrado por el equipo de plataforma</span>}</td>
                    </tr>;
                  })}</tbody>
                </table>
              </div>
            )}
          </section>

          {canConfigure && <section className="b89Panel" aria-labelledby="b89-dlp-install">
            <div className="b89Panel__header"><h2 id="b89-dlp-install">Agregar un equipo</h2></div>
            <p className="b89Dlp__intro">Crea una clave de un solo uso para instalar Ferrispector en otro equipo. El instalador registra la PC con el SOC; después aparecerá aquí y recibirá la política. La clave solo se muestra una vez y vence en 30 minutos.</p>
            {enrollmentToken ? (
              <div className="b89Dlp__token" role="status">
                <label htmlFor="b89-dlp-token">Clave de instalación de un solo uso</label>
                <div><Mono>{enrollmentToken}</Mono><EuiButtonEmpty size="s" onClick={() => { void navigator.clipboard?.writeText(enrollmentToken); }}>Copiar</EuiButtonEmpty></div>
                {enrollmentExpires && <p>Vence <Timestamp iso={enrollmentExpires} />. Cierra o recarga esta pantalla después de copiarla.</p>}
              </div>
            ) : (
              <EuiButton onClick={() => void createToken()} isLoading={enrollmentBusy}>Crear clave de instalación</EuiButton>
            )}
          </section>}
        </>
      )}
      {revokeTarget && (
        <EuiConfirmModal
          title={`Revocar credencial de ${revokeTarget.hostname}`}
          aria-label={`Confirmar revocación de ${revokeTarget.hostname}`}
          onCancel={() => setRevokeTarget(null)}
          onConfirm={() => void revokeEndpoint()}
          cancelButtonText="Mantener acceso"
          confirmButtonText="Revocar credencial"
          buttonColor="danger"
          confirmButtonDisabled={revoking}
          defaultFocusedButton="cancel"
        >
          <p>El equipo dejará de recibir cambios de política en su siguiente consulta.</p>
          <p>Esto no desinstala Ferrispector ni detiene el escaneo local. La credencial revocada ya no podrá sincronizar ni confirmar revisiones.</p>
        </EuiConfirmModal>
      )}
    </B89Page>
  );
}

function ErrorCallOutCompact({ error, retry }: { error: unknown; retry: () => void }) {
  return <ErrorCallout error={error} onRetry={retry} />;
}
