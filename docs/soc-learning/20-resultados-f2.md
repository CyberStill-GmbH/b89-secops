# Resultados F2 · prototipos de las fichas 1, 2, 3, 4 y 6

Fecha: 2026-11-24. Código, datos y tablas completas: `research/soc-lab/`, con `RESULTS.md` generado
por `run-all.ts` y las comparaciones pareadas por `paired.py`. Todo es **sintético** (30 semillas
× 180 días, ~170 alertas/día) con números aleatorios comunes: cada política ve exactamente el
mismo tráfico, así que las diferencias se miden **pareadas**. Las cifras sirven para comparar
políticas, no son predicciones de producción.

## Lo más importante

1. **La política de activación no protege contra la imitación exacta; solo el muestreo y la deriva
   lo hacen.** El atacante que copia la huella de un patrón aprobado suprime ~24 TP por corrida con
   **cualquier** política (E1, columna «del atacante»: 23–27). Sin muestreo suprime el 100 % (92,5
   de 92,5).
2. **El muestreo adaptativo empeora la defensa (contradice la ficha 2 de F1).** Con el mismo
   presupuesto, revisar más donde hay más incertidumbre dejó pasar **+24,3 ± 5,9** TP del atacante
   más que el uniforme (peor en 28 de 30 semillas). El atacante va a los patrones maduros y de mucho
   volumen, justo los que el adaptativo deja en el piso del 2 %. Descarté Stackelberg en F1 por
   falta de un modelo del atacante; este resultado muestra que la elección del atacante sí importa.
3. **La política jerárquica (ficha 3) da el mejor equilibrio observado.**
   - Frente al conteo actual N = 5: **−31,4 ± 9,2 TP suprimidos (−34 %)** y **−1,8 ± 0,6
     patrones inseguros activos (−73 %)**, a cambio de **−2,2 ± 0,9 pp de cobertura**.
   - **Domina** al conteo N = 10: +1,4 pp de cobertura, −15,8 TP suprimidos y −1,1 patrones
     inseguros, con IC pareados que excluyen 0.
4. **Clopper–Pearson (ficha 1) cumple su garantía, pero sola cuesta mucha cobertura.** Con
   q = 0,97 baja los patrones inseguros activos de 2,43 a 0,03 y los TP suprimidos un 56 %, pero
   pierde 25 pp de cobertura. Con q = 0,99 la cobertura cae al 8,5 %.
5. **CUSUM (ficha 6) detecta lo que el estático no ve.** Con ≤ 0,1 falsas alarmas al mes detecta
   el 100 % de los cambios ×2 (mediana 29 h), ×3 (11 h) y rampa a ×3 en 72 h (49 h). El
   multiplicador estático del diseño (piso 10/h) no detecta ninguno a tasas bajas (0,5/h).
6. **Los canarios (ficha 4) funcionan y encontraron un defecto de producción.**
   - 0 de 500 variantes autocerradas en cada uno de los 10 tipos de casi-coincidencia y guarda.
   - De las copias exactas, 22 de 500 (4,4 %) **no** se reconocen como el mismo patrón. Causa: la
     normalización de archivos temporales no reemplaza nombres que solo tienen letras hex
     (`tmpcbbf.ps1`), y sí los que tienen un dígito (`tmp4f2a.ps1`).
   - La prueba de propiedades lo confirma: 45 de 1000 pares difieren.
   - Es un defecto de **cobertura**, no de seguridad (una huella distinta escala, nunca cierra).

## E1 · Riesgo frente a cobertura (fichas 1 y 3)

Extracto. La tabla completa con 13 políticas está en `research/soc-lab/RESULTS.md`. Valores
medios ± IC 95 % sobre 30 semillas, con muestreo uniforme del 10 %.

| Política | Cobertura (%) | TP suprimidos / corrida | Del atacante | Patrones inseguros activos (θ > 3 %) |
|---|---:|---:|---:|---:|
| conteo N=5 (línea base) | 66,9 ± 2,3 | 93,2 ± 13,1 | 25,7 ± 5,1 | 2,43 ± 0,59 |
| conteo N=10 | 63,3 ± 2,5 | 77,6 ± 10,3 | 25,6 ± 5,3 | 1,77 ± 0,37 |
| conteo N=40 | 47,3 ± 2,3 | 49,9 ± 7,0 | 26,9 ± 5,8 | 0,30 ± 0,17 |
| CP q=0,95 | 53,7 ± 1,9 | 54,4 ± 7,9 | 23,7 ± 5,1 | 0,27 ± 0,16 |
| CP q=0,97 | 42,1 ± 1,7 | 40,6 ± 7,3 | 23,6 ± 5,2 | 0,03 ± 0,07 |
| jerárquica q=0,97 | 64,8 ± 2,5 | 61,9 ± 8,4 | 24,7 ± 5,2 | 0,67 ± 0,29 |
| jerárquica q=0,99 | 38,1 ± 2,3 | 32,6 ± 6,0 | 23,0 ± 5,1 | 0,03 ± 0,07 |

Comparaciones pareadas (A − B; IC 95 %; «>0 en k/30» = semillas donde A supera a B):

| A − B | Δ cobertura (pp) | Δ TP suprimidos | Δ inseguros activos |
|---|---:|---:|---:|
| jerárquica q=0,97 − conteo N=5 | −2,18 ± 0,86 (7/30) | −31,37 ± 9,20 (1/30) | −1,77 ± 0,61 (0/30) |
| jerárquica q=0,97 − conteo N=10 | +1,44 ± 0,91 (23/30) | −15,77 ± 6,56 (8/30) | −1,10 ± 0,38 (0/30) |
| CP q=0,97 − conteo N=5 | −24,89 ± 1,72 (0/30) | −52,63 ± 11,12 (0/30) | −2,40 ± 0,58 (0/30) |
| CP q=0,95 − conteo N=20 | −3,86 ± 1,34 (3/30) | −9,73 ± 6,27 (7/30) | −0,73 ± 0,26 (1/30) |
| jerárquica q=0,99 − CP q=0,97 | −3,96 ± 1,51 (6/30) | −7,97 ± 4,54 (3/30) | +0,00 ± 0,09 (1/30) |

**Lectura.**
- Ninguna política llega a «cero TP suprimidos». Debajo de cualquier activación queda el piso
  del atacante mimético (~24 por corrida), que solo baja con más revisión o con detección de
  deriva.
- La cifra es coherente con un cálculo simple: con una revisión del 10 % y un 98 % de acierto del
  revisor, un patrón atacado deja pasar en media `(1 − 0,098)/0,098 ≈ 9,2` TP antes de la primera
  revisión que lo pausa; por 3 patrones, ~28, frente a ~24 observados.

**Envenenamiento (E1b).** Una cuenta comprometida que etiqueta FP la mitad de lo que revisa en una
regla riesgosa durante 60 días añadió TP suprimidos en las tres políticas, pero en ninguna la
diferencia es estadísticamente clara:

| Política | Sin veneno | Con veneno |
|---|---:|---:|
| conteo N=5 | 93,2 | 99,7 |
| CP q=0,97 | 40,6 | 42,0 |
| jerárquica q=0,97 | 61,9 | 68,9 |

La jerárquica muestra la mayor sensibilidad relativa, como predecía la ficha, pero el experimento
es **débil** (una sola regla y un solo nivel de veneno). No basta para descartar el riesgo.

## E2 · Muestreo con el mismo presupuesto (ficha 2)

| Política | Muestreo | Revisiones | TP del atacante suprimidos | Días hasta pausar (mediana) |
|---|---|---:|---:|---:|
| conteo N=5 | sin muestreo | 0 | 92,5 ± 3,3 | ∞ |
| conteo N=5 | uniforme 10 % | 2791 | 25,7 ± 5,1 | 7 |
| conteo N=5 | adaptativo 10 % (piso 2 %) | 2996 | 50,0 ± 6,8 | 17 |
| CP q=0,97 | uniforme 10 % | 1765 | 23,6 ± 5,2 | 5 |
| CP q=0,97 | adaptativo 10 % (piso 2 %) | 1817 | 32,1 ± 6,1 | 7 |

- El adaptativo gastó además un 2–7 % **más** revisiones: la calibración del presupuesto usa la
  tasa esperada, no la observada. Aun así fue peor.
- **Horvitz–Thompson.** La prueba de propiedades confirma que el estimador no tiene sesgo de
  muestreo (error medio < 0,3 pp en 1000 repeticiones con π desiguales).
- En la simulación aparece un sesgo de **−0,47 pp** que no viene del muestreo, sino del
  **revisor**: etiqueta TP el 0,5 % de los FP. Por eso la precisión publicada debe usar etiquetas
  adjudicadas (dos revisores) o corregir por la tasa de error del revisor.

## E3 · Deriva (ficha 6)

| Escenario | Detector | Detecta | Retraso mediano | Falsas alarmas/mes |
|---|---|---:|---:|---:|
| escalón ×2 | estático 3×p95 (piso 10) | 0 % | ∞ | 0,00 |
| escalón ×2 | CUSUM h = 6,6 | 100 % | 29 h | 0,08 |
| escalón ×3 | estático | 0 % | ∞ | 0,00 |
| escalón ×3 | CUSUM | 100 % | 11 h | 0,08 |
| rampa a ×3 en 72 h | estático | 1 % | ∞ | 0,00 |
| rampa a ×3 en 72 h | CUSUM | 100 % | 49 h | 0,08 |
| ráfaga legítima ×5 · 2 h | CUSUM | — | — | 0,09 (≈ sin cambio: 0,07) |

**Salvedad de justicia.** El estático tuvo 0 falsas alarmas y CUSUM se calibró a ≤ 0,1/mes,
así que CUSUM juega con una tolerancia algo mayor. Aun así, la ceguera del estático viene de su
**piso de 10 alertas por hora**: con tasas bajas no puede alarmar nunca. El problema es de diseño
y no depende del umbral.

## E4 · Canarios (ficha 4)

| Variante | Autocerradas / 500 |
|---|---:|
| otro hash, destino, puerto, usuario, equipo, proceso padre o línea de comando | **0** en cada una |
| misma huella con P2, activo crítico o identidad privilegiada | **0** en cada una |
| copia exacta | 478 (22 no reconocidas por el defecto de normalización) |

La decisión es un **modelo** del diseño §7; el motor no existe. El valor demostrado es el método:
un canario de casi-coincidencia mide las salvaguardas sobre la huella real y destapa defectos de
normalización.

## Veredictos actualizados

| Ficha | F1 | Después de F2 |
|---|---|---|
| 1 · Clopper–Pearson | Adoptar | **Adoptar como piso de seguridad** (p. ej. q = 0,90–0,95), no como regla única: sola cuesta 25 pp de cobertura con q = 0,97. |
| 2 · Muestreo PRF + HT | Adoptar / prototipar adaptativo | **Adoptar la PRF uniforme con clave y HT con etiquetas adjudicadas. Descartar el adaptativo por incertidumbre** (empeora frente al atacante mimético). Próximo experimento: subir π en patrones maduros y de mucho volumen (lo opuesto). |
| 3 · Jerárquica | Prototipar | **Candidata principal**: domina a N = 10 y reduce un 34 % los TP suprimidos frente al conteo actual. Necesita un experimento de envenenamiento más fuerte antes de un ADR. |
| 4 · Canarios | Prototipar | **Adoptar** cuando exista el motor; el método ya se demostró (0 violaciones y un defecto real encontrado). |
| 6 · CUSUM | Prototipar | **Adoptar en sombra**: detecta cambios ×2 en ~1 día con < 0,1 falsas alarmas al mes. El piso estático del diseño (§7.3) debe revisarse. |

## Defecto de producción encontrado (sin corregir: F2 no toca producción)

`packages/contracts/src/observables/index.ts`, función `tempLeaf`: reemplaza por `{N}` solo los
tramos hex que contienen al menos un dígito. `tmpcbbf.ps1` queda tal cual y `tmp4f2a.ps1` pasa a
`tmp{N}.ps{N}`.
- **Efecto:** ~2 % de los eventos con archivo temporal generan una huella distinta para el mismo
  comportamiento; se pierde cobertura de autocierre y de agrupación.
- **Seguridad:** ninguna; una huella distinta escala.
- **Arreglo propuesto:** normalizar el nombre completo del archivo temporal (sin extensión) a
  `{N}`, subir `OBSERVABLES_NORMALIZER_VERSION` a `2` y usar la prueba de propiedades del
  laboratorio como regresión.

## Limitaciones

- Mundo, analistas y atacante son modelos con supuestos explícitos (`research/soc-lab/README.md`);
  no hay datos reales.
- El atacante elige los patrones de más volumen; otras estrategias (patrones nuevos, de bajo
  volumen, varios a la vez) no se probaron.
- No se probó la **combinación** de jerárquica + PRF uniforme + CUSUM, que es la propuesta lógica
  para F3.
- La prueba de propiedades de la huella **falla** (45/1000) por el defecto descrito; se dejó así a
  propósito como evidencia.
