# Innovación técnica para el SOC que aprende (F0–F1)

Fecha: 2026-11-24 · rama `feat/soc-learning-stage-a` @ `cb01d94` · **solo propuesta, nada implementado**.

Reglas de lectura:
- Todo número marcado **[calc]** se calculó en esta sesión con fórmulas exactas.
- Ningún resultado de simulación se presenta como obtenido: los prototipos son F2.
- Las referencias bibliográficas se citan de memoria y **no se verificaron en esta sesión**: van marcadas **[pv]** (por verificar) y se confirman antes de usarlas en un ADR.

Las decisiones fijas del proyecto se respetan en todas las fichas:
- fail-closed;
- el modelo propone y el código decide;
- los cierres de la IA no cuentan como evidencia de FP;
- P1/P2 nunca se autocierran ni se colapsan.

---

## F0 · Estado actual (con evidencia)

| Pieza | Qué hace hoy | Evidencia |
|---|---|---|
| Huella | SHA-256 de JSON canónico sobre regla, nombre de la regla, sujeto (usuario, host o IP) y comportamiento (proceso, padre, comando, hash, archivo, destino y puerto). Es `fine` solo con regla + sujeto + comportamiento. Igualdad **exacta**: no existe la noción de «parecido». | `modules/detection/src/fingerprint.ts:114`, `:141`, `:153` |
| Normalización | Redacción de secretos y marcadores para timestamps, GUID, hex, rutas temporales y perfiles. | `packages/contracts/src/observables/index.ts` |
| Cobertura | Con fixtures: 6 % de huella fina en total. Cloudflare 98 %, red 11 %, nube 0 %. | `docs/soc-learning/14-cobertura-huella.md` |
| Agrupación | Por huella exacta, con ventana de 24 h, tramo de 7 días y tope de 500 alertas. Fila del grupo bloqueada con `FOR UPDATE`. P1/P2 `collapsible: false`. | `modules/soc/src/alert-group.ts:144`, `:162`, `:164` |
| Correlación | Claves `user:`/`ip:`, repetición, cadenas de compromiso en ventana de 24 h. | `modules/detection/src/correlation.ts:58-61` |
| Decisión (motor) | **No existe todavía** (etapas D–F). | `docs/soc-learning/01-diseno.md` §7 |
| Decisión (Analista IA) | `KNOWN_BENIGN_PATTERN` exige ≥ 5 FP (configurable), 0 TP, < 2 fuentes y < 2 tácticas. El cierre automático exige además P3/P4 y ≥ `closeMinHistory` (3). Cuenta **solo cierres humanos** desde la etapa A. | `modules/assistant/src/investigations/policy.ts:46`, `actions.ts:102`, `:104`, `:174`, `:191` |
| Feedback del correlador | Par (regla, entidad) con ≥ 3 FP humanos y ratio ≥ 0,8 → propuesta. Por defecto no suprime. | `services/b89-correlator/internal/feedback/feedback.go:26`, `:36`, `:105`, `:226` |
| Muestreo de revisión | Diseñado (10 %, HMAC); **no implementado**. | diseño §7.1 punto 9 |
| Auditoría | Cadena hash por tenant (`previousHash` → `hash`) y triggers append-only. No hay anclaje externo ni firma. | `platform/audit/src/hash-chain.ts:44`, `:72`, `:80`; `file-archive.ts` |
| Envío a LLM | El seudonimizador reemplaza solo **correos e IPv4** por marcadores estables dentro de una conversación (`<usuario_1>`, `<ip_2>`); el propio archivo declara ese alcance. Hostnames, IPv6, rutas y líneas de comando viajan en claro. | `modules/assistant/src/pseudonymizer.ts:1-17`; `investigations/evidence-pack.ts:295` |
| Canarios | Existen canarios **de canal** (¿llegó el evento?), no de calidad de decisión. | `wazuh/platform-monitoring/b89_canary.py:1-20` |

**Lectura cuantitativa del estado actual [calc].** Un patrón con *n* confirmaciones y 0 errores
tiene una cota inferior unilateral al 95 % para su precisión (Clopper–Pearson) de `0,05^(1/n)`:

| n | 5 | 10 | 30 | 60 | 100 | 150 | 300 |
|---|---|---|---|---|---|---|---|
| Cota inferior de precisión | 0,549 | 0,741 | 0,905 | 0,951 | 0,971 | 0,980 | 0,990 |

Hacen falta **n ≥ 99** confirmaciones sin error para garantizar ≥ 97 %, y **n ≥ 299** para 99 %.
Los umbrales actuales (3–5 FP) solo garantizan un ~55 % de precisión en el peor caso compatible
con los datos. Esto no prueba que hoy se suprima mal; prueba que «cero TP suprimidos» **no se
puede afirmar** con esos conteos. Es el hallazgo que más pesa en el ranking.

---

## Ranking valor / esfuerzo

| # | Ficha | Problema | Valor | Esfuerzo | Veredicto |
|---|---|---|---|---|---|
| 1 | P2-A Cotas exactas + decisión de costo asimétrico | P2 | Alto | Bajo | **Adoptar** (prototipo de validación) |
| 2 | P3-A / P4-C Muestreo con PRF con clave + Horvitz–Thompson + asignación por incertidumbre | P3, P4 | Alto | Bajo–medio | **Adoptar / prototipar** |
| 3 | P2-C Beta-Binomial jerárquico (shrinkage regla → fuente) | P2, P3 | Alto | Medio | **Prototipar** |
| 4 | P3-B Canarios de casi-coincidencia (TP sintéticos) | P3, P7 | Alto | Medio | **Prototipar** |
| 5 | P6-A Anclaje externo de la cadena de auditoría (+ firma híbrida) | P6 | Medio–alto | Bajo | **Adoptar** |
| 6 | P7-A CUSUM / Page–Hinkley sobre la tasa de un patrón | P7 | Medio | Bajo | **Prototipar** |
| 7 | P3-C CUSUM por analista sobre cierres FP | P3 | Medio | Medio | **Prototipar** |
| 8 | P6-C Minimización de envío a LLM por allowlist de campos | P6 | Medio | Bajo | **Adoptar** |
| 9 | P5-A Componentes conexos ponderados por IDF de entidad | P5 | Medio | Medio | **Prototipar** (comparar con Leiden) |
| 10 | P1-A MinHash/LSH sobre la línea de comando normalizada | P1 | Bajo hoy | Medio | **Posponer** (falta cobertura) |
| 11 | P4-A Erlang C para dimensionar el presupuesto de alertas abiertas por día | P4 | Bajo–medio | Bajo | **Posponer** (faltan tiempos medidos) |
| 12 | P2-B Control de riesgo conforme | P2 | Bajo | Medio | **Posponer** |
| 13 | P6-B TLS con KEM híbrido post-cuántico | P6 | Medio | Bajo (configuración) | **Verificar disponibilidad** |

Para F2 recomiendo: **1, 2, 3, 4 y 6**. Comparten simulador y métrica (TP suprimidos frente a
cobertura), y juntos responden a P2, P3, P4 y P7. Las fichas 5 y 8 no necesitan simulación: son
decisiones de ingeniería que pueden ir directo a ADR.

---

## Fichas

### 1 · P2-A — Cotas exactas por patrón y decisión de costo asimétrico

1. **Problema y evidencia.** La activación usa conteos fijos (`policy.ts:46`: 5; `feedback.go:36`:
   3) sin cuantificar la incertidumbre. La tabla de F0 muestra que *n* = 5 solo garantiza ~55 %.
2. **Formulación.** Para un patrón con *n* confirmaciones humanas adjudicadas y *k* errores (TP
   entre ellas):
   - cota inferior Clopper–Pearson `p_L = Beta⁻¹(α; n−k, k+1)`, que con *k* = 0 da `α^(1/n)` [calc];
   - activar solo si `p_L ≥ 1 − ε`;
   - decisión de costo: autocerrar si `E[costo] = (1 − p̂)·C_TP_suprimido < C_revisión`, con
     `C_TP_suprimido ≫ C_revisión` (p. ej. 1000:1) y `p̂` la cota inferior, no la media.

   Complejidad O(1) por patrón (cuantil Beta).
3. **Supuestos.**
   - Confirmaciones independientes y de la misma distribución que el tráfico futuro. Un
     adversario lo viola si **imita el patrón después de aprobado**; por eso se combina con la
     huella exacta y con P3-B y P7-A.
   - Las confirmaciones pegadas en el tiempo no son independientes. Mitigación: contar **días
     distintos** (diseño §5.1) o usar el tamaño efectivo de la muestra.
4. **Línea base.** «≥ N FP y 0 TP» (lo actual). Se elige porque es lo que hay.
5. **Validación.** Monte Carlo: patrones con tasa TP verdadera θ ∈ {0; 0,5 %; 1 %; 5 %}, flujo de
   confirmaciones y atacante que entra en el momento *t*. Métricas: TP suprimidos por cada 10 000
   autocierres y cobertura (fracción autocerrable), frente a la línea base.
6. **Beneficio y costo.**
   - Beneficio: una garantía declarada («precisión ≥ 97 % con 95 % de confianza»).
   - Costo: casi ninguno en código.
   - Efecto colateral **esperado y deseable**: menos cobertura al principio (hacen falta ~99
     confirmaciones para el 97 %), lo que obliga a apoyarse en P2-C para reglas con poco volumen.
7. **Veredicto:** adoptar. Prototipo solo para medir el costo en cobertura.

### 2 · P3-A + P4-C — Muestreo con PRF con clave, estimador sin sesgo y asignación por incertidumbre

1. **Problema y evidencia.** El muestreo del 10 % está diseñado pero no implementado. Un 10 %
   uniforme detecta poco [calc]:
   - con una tasa real de TP del 1 % entre lo autocerrado, revisar 30 alertas detecta al menos un
     TP con probabilidad 0,26; revisar 100, con 0,63; y hacen falta ~300 para 0,95;
   - con 0,5 %: 0,14, 0,39 y 0,78 respectivamente.
2. **Formulación.**
   - Inclusión `HMAC(k, alert_id) / 2²⁵⁶ < π_i`, con `π_i` por patrón.
   - Precisión estimada con Horvitz–Thompson [pv]: `P̂ = Σ_{i∈S} y_i/π_i ÷ Σ_{i∈S} 1/π_i`
     (estimador de razón).
   - `π_i` asignado por incertidumbre: mayor donde la posterior de P2-C es más ancha (Thompson
     sampling o regla «enviar a revisión si una muestra de la posterior < umbral») [pv]. Con
     `π_i ≥ π_min` (p. ej. 2 %) para que ningún patrón quede sin auditar y el estimador siga
     definido.
   - O(1) por alerta.
3. **Supuestos.**
   - El atacante no conoce `k` (secreto en el gestor de secretos). Si lo conoce, puede evitar la
     muestra.
   - El alert_id no lo controla el emisor del evento. En B89 se deriva del hash de la clave de
     idempotencia (`promotion.ts`), que incluye el `recordId` del evento. Un atacante con
     control del `recordId` podría **buscar** IDs fuera de muestra; mitigación: la PRF usa además
     un nonce del servidor que no se persiste en el evento.
4. **Línea base.** Muestreo uniforme del 10 % con PRF (lo que dice el diseño).
5. **Validación.** Simulación con patrones heterogéneos. Métricas:
   - sesgo y varianza del estimador de precisión frente a la verdad;
   - tiempo hasta detectar un patrón que empezó a fallar;
   - todo con el **mismo presupuesto** de revisiones que la línea base.

   Prueba de propiedad: con `π` conocidas, el estimador es insesgado en 1000 repeticiones.
6. **Beneficio y costo.** Detección más rápida con el mismo presupuesto de revisiones (a medir;
   no se afirma cuánto). Costo bajo: una tabla de `π` y un cálculo por alerta.
7. **Veredicto:** adoptar la PRF y Horvitz–Thompson; prototipar la asignación adaptativa.

### 3 · P2-C — Modelo Beta-Binomial jerárquico (shrinkage entre patrones)

1. **Problema y evidencia.** Con el volumen del SOC (decenas a cientos de alertas al día,
   `docs/18:303`), la mayoría de los patrones nunca llegará a *n* ≈ 99 (ficha 1). Tratar cada
   patrón aislado deja sin cobertura a las reglas de bajo volumen.
2. **Formulación.**
   - `θ_patrón ~ Beta(μ_r·κ_r, (1−μ_r)·κ_r)`, con hiperparámetros por regla y estos a su vez por
     fuente.
   - Posterior conjugada por patrón; activar si `P(θ_TP < ε | datos) ≥ 1 − α`.
   - Ajuste por empírico-Bayes (momentos o máxima verosimilitud marginal) [pv]: O(número de
     patrones) por ajuste.
3. **Supuestos.**
   - Patrones de la misma regla son intercambiables. Un atacante que logra que una regla
     acumule muchos FP «limpios» **contamina el prior** de sus patrones hermanos (envenenamiento).
   - Mitigación: el prior solo **reduce** el conteo exigido hasta un piso (p. ej. *n* ≥ 10), nunca
     lo elimina; los priors de reglas con una táctica de alto impacto quedan fijados en
     pesimistas.
4. **Línea base.** Ficha 1 (cota por patrón aislado).
5. **Validación.** Simulación con reglas heterogéneas (algunas con θ alto escondido) y un
   atacante que envenena una regla. Métricas: cobertura ganada frente a ficha 1 con TP suprimidos
   ≤ al mismo objetivo, y robustez ante el envenenamiento.
6. **Beneficio y costo.** Posible ganancia grande de cobertura en reglas de poco volumen (a medir).
   Costo medio: estimación y explicación al analista («el patrón hereda confianza de su regla»).
7. **Veredicto:** prototipar.

### 4 · P3-B — Canarios de casi-coincidencia (TP sintéticos)

1. **Problema y evidencia.** El canario actual mide si el canal funciona
   (`b89_canary.py:1-20`); nada mide si las **salvaguardas** del motor funcionan en producción.
   La huella exacta cierra por construcción un evento idéntico a un patrón aprobado; el riesgo
   real está en las variantes.
2. **Formulación.**
   - Inyectar periódicamente eventos sintéticos marcados en un **registro sellado** (no en el
     evento) que comparten regla y sujeto con un patrón activo pero difieren en un componente
     (hash, destino, padre, usuario) o activan una guarda (P2, activo crítico).
   - Invariante: **nunca** se autocierran; deben escalar.
   - Métrica: tasa de violación = canarios autocerrados / canarios inyectados, que debe ser 0.
   - O(patrones activos) inyecciones por día.
3. **Supuestos.**
   - El canario no se distingue del tráfico real en el motor (si el motor lo reconoce, la
     prueba pierde valor). El registro sellado lo consulta solo el verificador.
   - Riesgo operativo: contaminar métricas y colas. Mitigación: identidad de tenant/fuente
     sintética, exclusión de métricas y avisos por el registro, y cierre automático del canario
     por el verificador tras el veredicto.
4. **Línea base.** Pruebas unitarias y adversariales de la Fase 4 (offline).
5. **Validación.** En simulación primero: atacante mimético frente a la combinación huella +
   guardas, con canarios midiendo. Luego en sombra.
6. **Beneficio y costo.** Convierte «cero TP suprimidos» en algo **medido continuamente** para
   la clase de ataque más probable. Costo medio (inyección por fuente, verificador, aislamiento).
7. **Veredicto:** prototipar (simulador en F2; integración en producción, solo con ADR).

### 5 · P6-A — Anclaje externo de la cadena de auditoría y firma híbrida

1. **Problema y evidencia.** La cadena hash detecta manipulación parcial (`hash-chain.ts:72-80`),
   pero quien tenga escritura en la base puede **recalcular la cadena entera** y nada externo lo
   delataría. No hay firma ni anclaje.
2. **Formulación.**
   - Cada hora o cada día, la raíz de Merkle de las cabezas de cadena por tenant se firma con una
     clave de KMS y se escribe en almacenamiento WORM (S3 Object Lock, ya previsto en
     `docs/05`).
   - Verificar = recomputar la raíz y comparar.
   - Firma híbrida Ed25519 + ML-DSA (FIPS 204 [pv]) para anclas de larga vida (retención de
     auditoría de 5 años).
   - Nota de honestidad: «cosechar ahora, descifrar después» afecta a la **confidencialidad**, no
     a la integridad. La firma post-cuántica protege la validez a largo plazo de las anclas, no
     su secreto.
3. **Supuestos.** La clave de firma y el bucket WORM están fuera del alcance de quien administra
   la base. La disponibilidad de ML-DSA en el runtime (Node/OpenSSL o KMS) **está por verificar**.
4. **Línea base.** Cadena hash sin anclaje (lo actual).
5. **Validación.** Prueba: manipular y recalcular la cadena en una base de prueba; el verificador
   debe detectarlo contra el ancla. No requiere simulación estadística.
6. **Beneficio y costo.** Cierra un vector real de manipulación interna. Costo bajo: un job, una
   clave y un bucket.
7. **Veredicto:** adoptar (ADR directo). La parte híbrida, tras verificar el soporte.

### 6 · P7-A — Deriva de un patrón: CUSUM / Page–Hinkley sobre su tasa

1. **Problema y evidencia.** La huella exacta ya impide que un comportamiento **distinto**
   herede un patrón. La deriva que queda es «misma huella, otro contexto»: frecuencia, horario,
   ráfagas. El diseño usa un multiplicador estático (3× p95, §7.3), que reacciona tarde a cambios
   graduales y dispara con ráfagas legítimas.
2. **Formulación.**
   - CUSUM de Poisson [pv] sobre conteos por hora de cada patrón:
     `S_t = max(0, S_{t−1} + x_t·ln(λ₁/λ₀) − (λ₁−λ₀))`, alarma si `S_t > h`.
   - `λ₀` es la tasa del periodo de aprobación y `λ₁ = 2λ₀` el cambio a detectar.
   - Opcional: divergencia de Jensen–Shannon [pv] entre la distribución de hora del día del
     periodo de aprobación y la de los últimos 7 días.
   - O(1) por hora y patrón.
3. **Supuestos.** Llegadas aproximadamente Poisson y estacionarias en el periodo base (la
   estacionalidad diaria se trata con tasas por franja horaria). Un atacante «lento» que sube la
   tasa por debajo de `λ₁` no se detecta: lo cubren las fichas 2 y 4.
4. **Línea base.** Multiplicador estático 3× p95 + piso (diseño §7.3).
5. **Validación.** Simulación con cambios en escalón y en rampa y con ráfagas legítimas. Métricas:
   retraso medio de detección a igual tasa de falsas alarmas (ARL₀ fijado).
6. **Beneficio y costo.** Detección más temprana de patrones que dejan de ser válidos (a medir).
   Costo bajo.
7. **Veredicto:** prototipar.

### 7 · P3-C — Detección de envenenamiento por analista (CUSUM por actor)

1. **Problema y evidencia.** La etapa A cuenta solo cierres humanos, pero una cuenta humana
   comprometida o un analista negligente puede fabricar confirmaciones. El diseño exige 2
   analistas distintos y como máximo 2 confirmaciones por analista (§5.2), sin vigilar la tasa.
2. **Formulación.** Para cada analista, CUSUM de Bernoulli [pv] sobre «cierre como FP» frente a
   su propia tasa histórica y frente a la del equipo en la misma regla. Una alarma congela sus
   confirmaciones como evidencia de patrones (no sus cierres) hasta revisión. O(1) por cierre.
3. **Supuestos.** Hay historial suficiente por analista. Con equipos pequeños, las tasas por
   analista son ruidosas.
4. **Línea base.** Las reglas de conteo del diseño (2 analistas, tope por analista).
5. **Validación.** Simulación de un actor que cambia de tasa en el momento *t*. Métricas: retraso
   de detección y falsas alarmas por analista-mes.
6. **Beneficio y costo.** Medio, con riesgo de fricción con el equipo. Debe ser transparente y
   revisable.
7. **Veredicto:** prototipar después de 1–6.

### 8 · P6-C — Minimización de lo enviado al LLM por allowlist de campos

1. **Problema y evidencia.** El seudonimizador cubre solo correos e IPv4
   (`pseudonymizer.ts:1-17`, alcance declarado en su cabecera). Hostnames, rutas de usuario y líneas de comando (que pueden
   contener nombres de clientes o secretos no redactados) viajan en claro dentro del paquete de
   evidencia (`evidence-pack.ts:295`).
2. **Formulación.**
   - **Allowlist** de campos por tipo de evidencia, en vez de enmascarar por regex.
   - Reutilizar la normalización y redacción de `b89.observables` para comandos y rutas.
   - Hostnames → marcadores por ejecución.
   - Medida: bytes y campos enviados por expediente, antes y después.
3. **Supuestos.** El modelo sigue siendo útil con menos detalle; se valida con el gold set del
   Analista IA (`07-plan-evaluacion.md`).
4. **Línea base.** El seudonimizador actual.
5. **Validación.** Sin simulación: prueba de propiedad «ningún valor fuera de la allowlist llega
   al prompt» sobre fixtures, y comparación de calidad del veredicto en el gold set.
6. **Beneficio y costo.** Reduce exposición de datos a un tercero. Costo bajo.
7. **Veredicto:** adoptar, coordinado con `06-llm-security.md` (de otra sesión; no se edita aquí).

### 9 · P5-A — Correlación: componentes conexos con IDF de entidad (frente a Leiden)

1. **Problema y evidencia.** La correlación actual une por clave compartida en una ventana
   (`correlation.ts:58-61`) y el correlador agrupa por pivote. Riesgo conocido: entidades «hub»
   (IP de NAT o VPN, cuentas de servicio) que unen todo en un componente gigante.
2. **Formulación.**
   - Grafo alerta–entidad en una ventana; peso de la entidad `idf = ln(N / df)`.
   - Se descartan las entidades con `df/N > τ` (hubs) y se toman componentes conexos con
     union-find: O(E·α(V)).
   - Comparar con Leiden [pv] sobre el mismo grafo: O(E) por iteración, con resolución a ajustar.
3. **Supuestos.** Las entidades están bien resueltas (la normalización de usuario y host ya
   existe). Un atacante puede **evitar** la unión cambiando de entidad: la correlación es un
   ahorro de volumen, no una defensa.
4. **Línea base.** Unión por clave compartida sin pesos (lo actual).
5. **Validación.** Simulación de incidentes con varios pasos sobre ruido de fondo y hubs.
   Métricas: pureza y completitud de los incidentes (ARI/NMI [pv]) y tamaño del componente mayor.
6. **Beneficio y costo.** Medio. Leiden solo si componentes conexos + IDF no alcanza: con cientos
   de alertas al día probablemente sí alcanza.
7. **Veredicto:** prototipar la comparación; adoptar la opción simple si empata.

### 10 · P1-A — Equivalencia aproximada: MinHash/LSH sobre la línea de comando

1. **Problema y evidencia.** La huella es exacta (`fingerprint.ts:141-153`): un argumento distinto
   da otra huella. Pero hoy solo el 6 % de las fixtures tiene huella fina y casi ninguna trae
   línea de comando (`14-cobertura-huella.md`).
2. **Formulación.**
   - Shingles de 3 tokens de `commandLine` normalizado; MinHash con 128 permutaciones [pv];
     LSH con 32 bandas × 4 filas.
   - Candidatos con similitud de Jaccard ≥ 0,8.
   - Uso **solo** para sugerir «parecida a la alerta X» o explicar deriva; **nunca** para
     autocerrar ni para unir a un patrón.
   - O(L) por alerta.
3. **Supuestos.** Similitud textual ≈ misma actividad. Un atacante puede forzar similitud (mismo
   comando con otro payload) para pasar desapercibido en un grupo: por eso no tiene efecto en la
   decisión.
4. **Línea base.** Huella exacta + `differingComponents`.
5. **Validación.** Pares sintéticos etiquetados (misma actividad con variantes, actividad
   distinta con texto parecido). Precisión y recall de «misma actividad» frente a la línea base.
6. **Beneficio y costo.** Bajo hasta que los extractores traigan líneas de comando.
7. **Veredicto:** posponer hasta cumplir las recomendaciones 1–4 de `14-cobertura-huella.md`.

### 11 · P4-A — Dimensionamiento con Erlang C

1. **Problema y evidencia.** No hay presupuesto de alertas abiertas por día ni SLA medido; el
   MTTR está definido pero no medido (`docs/detection-engineering/03-modelo-operativo.md`).
2. **Formulación.** M/M/c con llegadas λ por franja y servicio μ medido. Erlang C da
   `P(espera)` y el percentil del tiempo de espera; se elige el mínimo *c* (analistas) o el
   máximo λ admisible para un SLA. O(c).
3. **Supuestos.** Llegadas Poisson y servicio exponencial: las ráfagas lo violan, así que se usa
   por franja y con margen.
4. **Línea base.** Estimación manual.
5. **Validación.** Contraste con la cola real cuando haya tiempos medidos.
6. **Beneficio y costo.** Útil para planificar, no para decidir alertas. Costo bajo.
7. **Veredicto:** posponer hasta medir tiempos de trabajo.

### 12 · P2-B — Control de riesgo conforme (CRC)

1. **Problema y evidencia.** Se pide «error ≤ α» con garantía. CRC/split conformal [pv] ofrece
   una garantía **marginal** sobre un puntaje calibrado.
2. **Formulación.** Calibrar el umbral λ de un puntaje de confianza para que la pérdida esperada
   (TP suprimido) sea ≤ α sobre un conjunto de calibración intercambiable.
3. **Supuestos.** Intercambiabilidad: **la viola un adversario** y cualquier deriva. Además, el
   motor diseñado decide por patrones deterministas, no por un puntaje: no hay a qué aplicar CRC
   hoy. La garantía es marginal (sobre todas las alertas), no por patrón.
4. **Línea base.** Fichas 1 y 3, que dan garantías por patrón.
5. **Validación.** Prueba de propiedad: error empírico ≤ α en 1000 repeticiones bajo
   intercambiabilidad, y medir cuánto se rompe con deriva y con un atacante.
6. **Beneficio y costo.** Bajo hoy.
7. **Veredicto:** posponer. Reconsiderar si el Analista IA llega a decidir con un puntaje.

### 13 · P6-B — TLS con KEM híbrido post-cuántico

1. **Problema.** «Cosechar ahora, descifrar después» sí afecta a la confidencialidad de lo que
   viaja hoy: evidencias, exportes y llamadas al LLM.
2. **Formulación.** Preferir el grupo híbrido X25519 + ML-KEM-768 [pv] en TLS donde el
   balanceador, OpenSSL y los clientes lo soporten.
3. **Supuestos.** Disponibilidad real en ALB/CloudFront/Node de producción: **por verificar**.
4. **Línea base.** TLS 1.3 clásico.
5. **Validación.** Inspeccionar el grupo negociado en cada salto.
6. **Beneficio y costo.** Medio y de bajo costo si está disponible.
7. **Veredicto:** verificar disponibilidad; es configuración, no código del SOC.

---

## Descartadas y por qué

| Propuesta | Motivo |
|---|---|
| **Control PI/PID de umbrales** para mantener un volumen objetivo | Acopla la sensibilidad a la carga: una inundación sube los umbrales y suprime más justo cuando hay ataque. Un adversario lo explota a propósito. Viola fail-closed. |
| Juego de Stackelberg para la política de muestreo | Necesita una función de utilidad del atacante que no tenemos. La PRF con clave (ficha 2) ya hace la muestra impredecible; la ganancia marginal no es demostrable. |
| NCD (distancia normalizada por compresión) | O(n²) compresiones y sin ventaja demostrada sobre MinHash para líneas de comando cortas. |
| Distancia de edición entre árboles de procesos | No existe árbol de procesos en los datos (solo el padre inmediato, y rara vez). |
| Procesos de Hawkes para ráfagas | Con decenas a cientos de alertas al día no hay datos para estimarlos de forma estable; CUSUM (ficha 6) cubre la detección de cambios. |
| Count-Min / HyperLogLog | El volumen cabe en conteos exactos de Postgres; aproximar no aporta. |
| Privacidad diferencial en métricas internas | Con conteos pequeños el ruido destruye la utilidad. Se reconsidera solo para reportes que salen de la organización. |
| Recocido simulado / QUBO para el conjunto mínimo de exclusiones | El problema (cobertura de conjuntos sobre decenas de reglas y huellas) lo resuelve **exacto** un ILP en milisegundos, o un voraz con garantía ln(n). Recocido o QUBO solo añaden aleatoriedad sin óptimo garantizado. Si el asistente de tuning lo necesita: ILP. |
| Analogías termodinámicas para umbrales | Sin una formulación que gane a las fichas 1, 3 y 6; no pasa el filtro de evidencia. |
| **Algoritmos cuánticos** (Grover, QAOA, recocido cuántico) | Filtro de honestidad: ninguno tiene ventaja demostrada a estos tamaños. Grover da una aceleración cuadrática irrelevante para búsquedas de miles de elementos; QAOA y el recocido cuántico no tienen ventaja probada en cobertura de conjuntos de este tamaño frente a un ILP; el hardware disponible por nube es ruidoso, de pocos qubits útiles y con costo por tarea. Se descarta. La única pieza «cuántica» que se mantiene es la **criptografía post-cuántica** (fichas 5 y 13), que es clásica y estandarizada. |

---

## Propuesta para F2 (a tu elección, máximo 5)

Simulador único en `research/soc-lab/` (aislado de producción, semillas fijas):
- generador de patrones con θ heterogénea por regla;
- llegadas Poisson por franja y ráfagas;
- analistas con error;
- un **atacante mimético** que entra en el momento *t* copiando regla y sujeto y variando un
  componente (o, en el peor caso, la huella completa).

Métrica principal: **TP suprimidos frente a cobertura de autocierre**, con curvas riesgo–cobertura
de cada política contra la línea base.

| Elección sugerida | Qué se demuestra |
|---|---|
| 1 · P2-A | Costo de cobertura de una garantía declarada |
| 2 · P3-A/P4-C | Estimador insesgado (prueba de propiedad) y detección más rápida con el mismo presupuesto |
| 3 · P2-C | Cobertura recuperada en reglas de poco volumen sin superar el objetivo de TP suprimidos; robustez al envenenamiento |
| 4 · P3-B | Tasa de violación de salvaguardas medida (objetivo 0) |
| 6 · P7-A | Retraso de detección de deriva a igual tasa de falsas alarmas |

Las fichas 5 (anclaje de auditoría) y 8 (allowlist del LLM) no necesitan simulador: propongo
llevarlas directo a ADR cuando lo indiques.
