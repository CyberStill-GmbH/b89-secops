# ADR-029 — B89 SOC como plataforma SIEM/XDR y espacio de trabajo SOC

> **Contexto heredado de QAPAQ SecOps; vigente solo lo que recoge [docs/10-decisiones.md](../../10-decisiones.md).**
> Se conserva como historia; la arquitectura vigente es serverless sobre AWS ([02](../../02-arquitectura.md)).

> **Nota (2026-10-14):** la parte de «consola propia B89» de esta decisión fue reemplazada por la
> instrucción posterior del dueño: B89 SOC usa la UI de Wazuh rebrandeada de principio a fin
> (`docs/10-decisiones.md`, A6). Siguen vigentes B89 Cases, B89 Respond (antes Shuffle) y la visión SIEM/XDR.


- Estado: Accepted.
- Fecha: 2026-10-13.
- Responsables: Product Owner, SOC y Arquitectura.
- Sustituye: la decisión de producto descrita en `docs/deployment/b89-dashboard-wazuh-adaptation.md` que define Wazuh Dashboard adaptado como consola final.
- No sustituye: la vertical técnica del MVP de [ADR-024](024-microsoft-365-wazuh-mvp-vertical.md) ni la selección de Shuffle de [ADR-028](028-shuffle-soar-webhook-adapter.md).

## Contexto

B89 SOC se había descrito en algunos documentos principalmente como la consola
que complementa las alertas de Wazuh, y la adaptación de Wazuh Dashboard llegó a
presentarse como la interfaz final del producto. Esa descripción reduce el propósito
de B89 a una pantalla y deja en segundo plano sus responsabilidades de SIEM/XDR,
operación SOC, respuesta y aprendizaje institucional.

El producto debe integrar un motor de seguridad de código abierto y concentrar en
B89 la experiencia de operación, el contexto de la organización financiera y las
capacidades diferenciales que necesitan sus analistas. El MVP mantiene la ruta
Microsoft 365 → Wazuh → B89 aprobada por ADR-024. La evolución posterior debe
ampliar fuentes, investigación colaborativa y automatización sin crear un segundo
motor SIEM ni confiar la autorización de negocio a la interfaz.

## Decisión

B89 SOC es el producto SOC central de la Financiera B89: una plataforma SIEM/XDR
que integra recolección y detección de Wazuh con normalización, investigación,
coordinación operativa, respuesta gobernada y aprendizaje continuo. Wazuh es un
componente tecnológico del producto —motor de agentes, ingesta, reglas y alertas—,
no el nombre ni el límite de B89 SOC.

La experiencia final pertenece a B89 SOC. Después del MVP no se mantendrá un
Wazuh Dashboard independiente como consola principal del SOC. La consola B89 podrá
reutilizar componentes y capacidades compatibles de OpenSearch Dashboards/Wazuh
donde aporten valor, pero navegación, identidad de producto, flujos de investigación,
autorización y experiencia operativa serán de B89. El Dashboard de Wazuh podrá
conservarse temporalmente como herramienta técnica de administración o transición
mientras la consola equivalente de B89 cubre los casos operativos requeridos; su
retirada dependerá de paridad comprobada y no de una fecha supuesta.

**B89 Cases** es el espacio colaborativo de investigación y gestión de incidentes
dentro de B89 SOC, inspirado en los flujos de trabajo de TheHive. Permite que un
equipo revise señales que ameritan atención, asigne responsables, coordine tareas,
registre notas y evidencia con procedencia, mantenga una línea de tiempo auditable,
documente decisiones y preserve el resultado como antecedente histórico reutilizable.
La inspiración se limita a patrones de colaboración; B89 conserva su propio modelo
de dominio, controles, vocabulario y diseño. B89 Cases no constituye otro SIEM ni
una fuente paralela de alertas.

Después de estabilizar el MVP, B89 incorporará un SOAR no-code basado en Shuffle,
según ADR-028. B89 conservará el catálogo de acciones permitidas, permisos,
aprobaciones, alcance, versiones autorizadas, idempotencia, correlación, auditoría y
reconciliación. Los playbooks podrán invocar capacidades de Wazuh adaptadas a las
necesidades de la financiera mediante adapters controlados. Active Response seguirá
siendo una capacidad de ejecución de Wazuh cuando corresponda; no sustituye el
gobierno de acciones de B89 ni autoriza acciones por sí sola. El motor y editor
visual de Shuffle se habilitarán después del MVP tras superar los gates de seguridad,
integración y operación.

La visión del producto comprende un ciclo continuo de monitoreo, detección,
investigación, respuesta, mitigación y aprendizaje. El aprendizaje se materializa
con evidencia histórica, revisión de incidentes, mejora aprobada de detecciones y
playbooks, y retroalimentación verificable; no implica cambios autónomos en reglas o
respuestas sin validación humana y trazabilidad.

## Alcance por etapa

- **MVP:** mantener la única vertical empresarial aprobada —Microsoft 365 recolectado
  por Wazuh y consumido por B89—; completar triaje, investigación, incidentes,
  auditoría y operación de fuentes acordados. El MVP no se redefine como un reemplazo
  general de todas las funciones Wazuh ni como un XDR de cobertura universal.
- **Evolución post-MVP:** consolidar la consola propia B89 y B89 Cases; añadir
  fuentes XDR priorizadas por autorización y valor; habilitar Shuffle y playbooks
  financieros gobernados; incorporar lecciones y mejoras de detección con revisión.
- **No incluido por esta decisión:** migrar inmediatamente todo Wazuh, duplicar su
  ruleset, habilitar respuestas destructivas sin aprobación, prometer cobertura de
  todas las fuentes o afirmar que las capacidades futuras ya están operativas.

## Licenciamiento y sostenibilidad

La preferencia es construir sobre proyectos open source compatibles para evitar
costos de licencias propietarias de software en los componentes seleccionados. Esto
no equivale a costo total cero: permanecen infraestructura, almacenamiento,
conectividad, soporte, operación, seguridad, capacitación y mantenimiento. Antes de
cada adopción se revisarán la licencia, procedencia, obligaciones de redistribución,
compatibilidad, ciclo de soporte y costo operativo del proyecto.

La arquitectura modular permite que un equipo pequeño incorpore capacidades por
verticales y extienda el producto con adapters y módulos acotados. La modularidad no
justifica crear servicios, motores o abstracciones duplicadas sin una necesidad
validada, ownership y evidencia operativa.

## Consecuencias y guardas

- Los requisitos y documentación del producto describirán B89 SOC como
  plataforma; Wazuh y Shuffle se documentarán como componentes integrados.
- Se actualizarán progresivamente los documentos que todavía asignan al Wazuh
  Dashboard el papel de consola final. El plan de adaptación visual de ese Dashboard
  queda sustituido; las tareas de transición y migración de capacidades se conservan
  solo donde sean reutilizables para la consola B89.
- PostgreSQL y los servicios de B89 mantienen la fuente de verdad para casos,
  permisos, aprobaciones y auditoría. Alertas y eventos fuente mantienen su
  procedencia en Wazuh u otros proveedores; B89 no los altera para simular autoridad.
- Toda acción automatizada valida autorización en servidor, scope, aprobación
  aplicable, versión autorizada, límites e idempotencia; las operaciones ambiguas se
  reconcilian antes de reintentarse.
- La salida del Dashboard Wazuh requiere matriz de capacidades, pruebas de rol,
  búsqueda y respuesta operativa, exportación/retención, rendimiento, recuperación y
  rollback en un entorno autorizado.
- La afirmación de ahorro de licencias se limita a licencias de software seleccionadas;
  el presupuesto de operación debe incluir costos recurrentes no relacionados con
  licenciamiento.

## Criterios de revisión

Revisar esta decisión al aceptar el cierre del MVP, al habilitar la primera fuente
adicional, antes de desplegar Shuffle en producción o si una evaluación de licencia,
soporte, seguridad o costo cambia la selección de componentes.

## Referencias

ADR-024 — Vertical del primer MVP (no conservado en este repo) ·
[ADR-028 — Shuffle como motor SOAR (heredado)](028-shuffle-soar-webhook-adapter.md) ·
[Arquitectura vigente](../../02-arquitectura.md).
