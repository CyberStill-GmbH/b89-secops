# Resultados F3a · laboratorio del SOC que aprende

Generado por `pnpm exec tsx research/soc-lab/run-f3a.ts`. Semillas fijas; números aleatorios comunes entre políticas (mismo tráfico). Intervalos: **IC 95 % bootstrap** (2000 remuestreos de semillas, percentiles). Los valores son medias por corrida de 180 días (~170 alertas/día) salvo que se indique otra cosa.

_Datos sintéticos (simulador `research/soc-lab/src/sim2.ts`); no son cifras de producción._

Tabla CUSUM (presupuesto global 1 falsa alarma/mes sobre ~120 patrones → ARL₀ = 3600 días por patrón): λ₀=0,05→h=3,80 · λ₀=0,10→h=4,48 · λ₀=0,20→h=4,99 · λ₀=0,50→h=5,69 · λ₀=1,00→h=6,05 · λ₀=2,00→h=6,38 · λ₀=5,00→h=6,57 · λ₀=10,00→h=6,55 · λ₀=20,00→h=5,77 · λ₀=50,00→h=2,68.

Orden de llegada dentro del día: **aleatorio** (permutación con semilla). Una versión anterior procesaba las alertas del atacante siempre al final del día, lo que favorecía artificialmente al tope diario de E4; quedó corregido y todo se volvió a ejecutar.

«Combinada» = jerárquica q = 0,97 + piso Clopper–Pearson 0,90 + ≥ 2 analistas distintos + ≥ 3 días distintos + aprobación de dos personas (separación respecto de quienes firmaron la evidencia presentada) + CUSUM con presupuesto global + muestreo uniforme con clave del 10 %.

## E1 · Política combinada frente a N=5, N=10 y jerárquica sola

100 semillas. Atacante (a): copia exacta de los 3 patrones activos de más volumen, ~1 TP/día cada uno, días 90–119.

_Datos sintéticos (simulador `research/soc-lab/src/sim2.ts`); no son cifras de producción._

| Política | Alertas (denominador) | Autocierres | Cobertura % | TP suprimidos | …de ellos del atacante / inyectados | TP ponderados por impacto | Inseguros activos | Revisiones | Pausas CUSUM sin ataque |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| conteo N=5 (actual) | 42429 | 28771 | 68,2 [66,9; 69,5] | 91,8 [84,5; 99,7] | 26,9 / 89,0 | 328,4 [285,2; 374,1] | 1,92 | 2859 | 0,00 |
| conteo N=10 | 42429 | 27207 | 64,5 [63,2; 65,8] | 79,7 [73,5; 85,8] | 27,0 / 89,0 | 280,2 [245,4; 316,6] | 1,47 | 2704 | 0,00 |
| jerárquica sola | 42429 | 27916 | 66,2 [64,7; 67,7] | 63,3 [58,7; 67,7] | 26,6 / 89,0 | 214,1 [189,9; 240,4] | 0,27 | 2776 | 0,00 |
| combinada | 42429 | 17786 | 42,1 [41,0; 43,2] | 44,3 [40,9; 47,5] | 27,4 / 89,0 | 144,7 [124,0; 167,0] | 0,05 | 1770 | 5,27 |

Diferencias pareadas (combinada − X), media [IC 95 % bootstrap]:

| X | Δ cobertura (pp) | Δ TP suprimidos | Δ TP del atacante | Δ TP ponderados |
|---|---:|---:|---:|---:|
| conteo N=5 (actual) | -26,1 [-27,0; -25,2] | -47,6 [-55,1; -40,3] | 0,4 [-2,2; 3,1] | -183,7 [-227,3; -142,3] |
| conteo N=10 | -22,4 [-23,3; -21,4] | -35,4 [-41,1; -29,9] | 0,3 [-2,2; 2,9] | -135,5 [-166,6; -106,0] |
| jerárquica sola | -24,1 [-25,0; -23,1] | -19,0 [-22,7; -15,2] | 0,8 [-1,9; 3,4] | -69,3 [-89,8; -48,6] |

## E1b · Descomposición: qué pieza de la combinada cuesta cobertura

60 semillas. Cada fila añade UNA pieza a la jerárquica sola (salvo «combinada», que las suma todas). Δ = fila − jerárquica sola [IC 95 % bootstrap].

_Datos sintéticos (simulador `research/soc-lab/src/sim2.ts`); no son cifras de producción._

| Variante | Cobertura % | Δ cobertura (pp) | TP suprimidos | Δ TP suprimidos | TP del atacante / inyectados |
|---|---:|---:|---:|---:|---:|
| jerárquica sola | 66,0 [64,2; 67,9] | 0,0 [0,0; 0,0] | 66,9 [60,7; 72,9] | 0,0 [0,0; 0,0] | 29,2 / 88,2 |
| + piso CP 0,90 | 60,8 [59,0; 62,6] | -5,2 [-5,5; -4,9] | 57,5 [52,2; 62,5] | -9,4 [-12,9; -6,5] | 29,1 / 88,2 |
| + ≥ 2 analistas | 66,0 [64,2; 67,9] | 0,0 [0,0; 0,0] | 66,9 [60,7; 72,9] | 0,0 [0,0; 0,0] | 29,2 / 88,2 |
| + ≥ 3 días | 65,7 [63,8; 67,6] | -0,4 [-0,5; -0,2] | 65,2 [59,0; 71,2] | -1,7 [-2,9; -0,6] | 29,1 / 88,2 |
| + dos personas | 46,1 [44,7; 47,4] | -19,9 [-21,1; -18,9] | 50,9 [46,0; 55,6] | -16,0 [-19,7; -12,3] | 28,7 / 88,2 |
| + CUSUM | 65,4 [63,5; 67,2] | -0,7 [-0,9; -0,4] | 66,2 [60,0; 72,1] | -0,7 [-1,5; 0,1] | 29,1 / 88,2 |
| combinada | 41,9 [40,5; 43,3] | -24,2 [-25,3; -23,1] | 46,9 [42,1; 51,4] | -20,0 [-24,9; -15,4] | 28,9 / 88,2 |

## E2 · Atacantes múltiples (peor caso por política)

60 semillas por celda. Cada celda: TP del atacante suprimidos / inyectados (media por corrida) y, para (g), % de corridas en que el patrón plantado llegó a activarse.

_Datos sintéticos (simulador `research/soc-lab/src/sim2.ts`); no son cifras de producción._

| Atacante | conteo N=5 (actual) | jerárquica sola | combinada |
|---|---:|---:|---:|
| (a) mayor volumen | 29,9 / 88,2 (34 %) | 29,2 / 88,2 (33 %) | 28,9 / 88,2 (33 %) |
| (b) menor volumen | 22,9 / 88,2 (26 %) | 23,4 / 88,2 (27 %) | 20,2 / 88,2 (23 %) |
| (c) bajo y lento (sustituye 30 % del tráfico; tasa total igual) | 23,1 / 241,4 (10 %) | 23,9 / 244,4 (10 %) | 22,3 / 251,7 (9 %) |
| (d) ráfagas: 7 TP juntos cada 7 días | 24,1 / 105,0 (23 %) | 25,3 / 105,0 (24 %) | 23,2 / 105,0 (22 %) |
| (e) conoce p, no la clave: se detiene tras 6 por patrón | 12,9 / 18,0 (72 %) | 12,9 / 18,0 (71 %) | 13,2 / 18,0 (73 %) |
| (f) cambia de patrón al ser pausado (3 TP/día) | 69,0 / 88,0 (78 %) | 68,8 / 88,0 (78 %) | 68,8 / 88,0 (78 %) |
| (g1) insider solo planta un patrón (1 TP/día, 180 días) | 7,1 / 177,6 (4 %) · activado en 100 % | 6,5 / 177,6 (4 %) · activado en 100 % | 0,0 / 177,6 (0 %) · activado en 0 % |
| (g2) colusión de 4 (2 etiquetan, 2 aprueban) | 7,1 / 177,6 (4 %) · activado en 100 % | 6,5 / 177,6 (4 %) · activado en 100 % | 8,2 / 177,6 (5 %) · activado en 85 % |

**Peor caso** (atacante que más TP logra suprimir, media por corrida):

- conteo N=5 (actual): (f) cambia de patrón al ser pausado (3 TP/día) — 69,0 TP suprimidos (78 % de lo inyectado).
- jerárquica sola: (f) cambia de patrón al ser pausado (3 TP/día) — 68,8 TP suprimidos (78 % de lo inyectado).
- combinada: (f) cambia de patrón al ser pausado (3 TP/día) — 68,8 TP suprimidos (78 % de lo inyectado).

## E3 · Autocierre solo en clases de bajo impacto

60 semillas. 30 % de las reglas son de alto impacto (peso 10); el resto, peso 1. Con la compuerta, en alto impacto solo se agrupa o baja prioridad (no hay autocierre).

_Datos sintéticos (simulador `research/soc-lab/src/sim2.ts`); no son cifras de producción._

| Política | Compuerta | Cobertura % | TP suprimidos | TP ponderados por impacto | Del atacante (ponderado) |
|---|---|---:|---:|---:|---:|
| conteo N=5 (actual) | no | 68,2 [66,5; 69,9] | 97,5 [87,2; 108,7] | 362,6 [304,0; 424,4] | 101,7 |
| conteo N=5 (actual) | sí | 47,2 [45,0; 49,3] | 74,6 [66,2; 83,2] | 74,6 [66,2; 83,2] | 28,5 |
| conteo N=5 (actual) | Δ (sí − no) | -21,0 [-23,0; -19,0] | -22,9 [-29,1; -17,0] | -288,0 [-348,3; -230,1] | -73,2 [-101,2; -49,3] |
| combinada | no | 41,9 [40,5; 43,3] | 46,9 [42,1; 51,4] | 168,2 [138,3; 199,3] | 99,8 |
| combinada | sí | 28,4 [26,9; 30,0] | 37,7 [33,8; 42,1] | 37,7 [33,8; 42,1] | 25,4 |
| combinada | Δ (sí − no) | -13,4 [-14,8; -12,0] | -9,2 [-12,5; -5,6] | -130,5 [-162,2; -99,5] | -74,4 [-100,7; -49,1] |

## E4 · Tope de radio de daño

60 semillas, política combinada. Tope = máximo de autocierres por patrón y día (el exceso va a una persona). Revisión forzada = tras N autocierres seguidos sin revisión humana, la siguiente alerta se revisa. Atacantes (a) y (f).

_Datos sintéticos (simulador `research/soc-lab/src/sim2.ts`); no son cifras de producción._

| Tope/día | Revisión forzada tras | Orden | Cobertura % | Revisiones | (a) TP del atacante | (f) TP del atacante | Δ cobertura vs sin topes (pp) |
|---|---|---|---:|---:|---:|---:|---:|
| ∞ | ∞ | aleatorio | 41,9 [40,5; 43,3] | 1768 | 28,9 [25,0; 32,5] | 68,8 [66,4; 71,2] | 0,0 [0,0; 0,0] |
| ∞ | 20 | aleatorio | 41,2 [39,8; 42,6] | 1946 | 24,1 [20,8; 27,3] | 66,8 [64,3; 69,3] | -0,6 [-0,8; -0,4] |
| ∞ | 10 | aleatorio | 39,2 [38,0; 40,5] | 2402 | 20,2 [17,4; 22,9] | 58,8 [56,5; 61,1] | -2,6 [-3,1; -2,2] |
| 10 | ∞ | aleatorio | 41,1 [39,7; 42,5] | 1735 | 25,8 [22,6; 28,8] | 58,5 [55,4; 61,4] | -0,8 [-1,2; -0,4] |
| 10 | 20 | aleatorio | 40,4 [39,0; 41,8] | 1906 | 21,9 [19,1; 24,5] | 57,2 [54,2; 60,1] | -1,4 [-1,8; -1,1] |
| 10 | 10 | aleatorio | 38,6 [37,3; 39,9] | 2364 | 18,6 [16,1; 21,1] | 52,0 [49,0; 55,1] | -3,2 [-3,8; -2,7] |
| 5 | ∞ | aleatorio | 38,0 [36,6; 39,3] | 1596 | 19,6 [17,3; 21,8] | 31,9 [29,3; 34,7] | -3,9 [-4,5; -3,3] |
| 5 | 20 | aleatorio | 37,5 [36,2; 38,8] | 1761 | 17,6 [15,6; 19,6] | 32,3 [29,6; 35,3] | -4,4 [-5,0; -3,7] |
| 5 | 10 | aleatorio | 35,9 [34,7; 37,2] | 2188 | 14,8 [12,7; 17,1] | 32,3 [30,1; 34,6] | -6,0 [-6,6; -5,3] |
| 10 | ∞ | **atacante primero** | 41,1 [39,7; 42,4] | 1733 | 28,7 [25,3; 32,2] | 68,8 [66,7; 71,0] | -0,8 [-1,5; -0,0] |
| 5 | ∞ | **atacante primero** | 37,4 [36,1; 38,7] | 1571 | 27,1 [23,9; 30,4] | 66,5 [64,7; 68,4] | -4,4 [-5,2; -3,7] |

## E5 · Envenenamiento reforzado

40 semillas por celda. Todas las reglas riesgosas (θ ≈ 5 %) atacadas: un % de sus cierres lo firman insiders que siempre marcan FP. Política base: jerárquica q = 0,97 + piso CP 0,90, sin ataque externo. Celda: TP naturales suprimidos en las reglas envenenadas (media) · patrones inseguros activos al final.

_Datos sintéticos (simulador `research/soc-lab/src/sim2.ts`); no son cifras de producción._

| Nivel · insiders | ninguna | ≥ 2 analistas | ≥ 3 días | dos personas | las tres | conteo N=5 sin defensas |
|---|---:|---:|---:|---:|---:|---:|
| 1 % · 1 | 7,3 · 0,15 | 7,3 · 0,15 | 7,3 · 0,15 | 5,7 · 0,10 | 5,7 · 0,10 | 48,8 · 2,58 |
| 1 % · 2 | 7,3 · 0,15 | 7,3 · 0,15 | 7,3 · 0,15 | 6,4 · 0,10 | 6,4 · 0,10 | 48,8 · 2,58 |
| 5 % · 1 | 7,8 · 0,15 | 7,8 · 0,15 | 7,8 · 0,15 | 4,7 · 0,07 | 4,7 · 0,07 | 49,1 · 2,60 |
| 5 % · 2 | 7,8 · 0,15 | 7,8 · 0,15 | 7,8 · 0,15 | 6,3 · 0,10 | 6,3 · 0,10 | 49,1 · 2,60 |
| 20 % · 1 | 10,8 · 0,28 | 10,8 · 0,28 | 10,8 · 0,28 | 5,8 · 0,17 | 5,8 · 0,17 | 52,2 · 2,75 |
| 20 % · 2 | 10,8 · 0,28 | 10,8 · 0,28 | 10,8 · 0,28 | 6,8 · 0,15 | 5,0 · 0,05 | 52,2 · 2,75 |

## E6 · Detectores de deriva con presupuesto global de falsas alarmas

Falsas alarmas: se miden **en total** sobre P = 100 patrones sin cambio (tasas lognormales, mediana 1,2/día) y se reportan también **por patrón**. Cada detector calibra UN parámetro para ≤ 1 falsa alarma/mes **en total** (corrección por pruebas múltiples: por patrón ≤ 0.01/mes). Calibración en semillas 300+; medición en semillas 900+ (independientes). Retardo en días y **en alertas** del patrón desde el cambio hasta la alarma; 400 repeticiones por escenario.

_Datos sintéticos (simulador `research/soc-lab/src/sim2.ts`); no son cifras de producción._

| Detector | Parámetro | Falsas alarmas/mes total · por patrón | escalón ×2: detecta % · alertas mediana (p90) · días | escalón ×3: detecta % · alertas mediana (p90) · días | rampa a ×3 en 21 días: detecta % · alertas mediana (p90) · días | ráfaga +10 cada 7 días: detecta % · alertas mediana (p90) · días | bajo y lento (sustitución, tasa igual): detecta % · alertas mediana (p90) · días |
|---|---:|---:|---|---|---|---|---|
| CUSUM (h = c·tabla) | 0,98 | 0,89 · 0,009 | 98 % · 28 (51) · 10 | 100 % · 18 (27) · 4 | 100 % · 35 (78) · 15 | 100 % · 12 (65) · 0 | 3 % · 53 (119) · 54 |
| EWMA (r = 0,2) | 4,04 | 1,07 · 0,011 | 96 % · 33 (67) · 9 | 100 % · 19 (32) · 3 | 100 % · 38 (78) · 15 | 98 % · 11 (92) · 0 | 5 % · 27 (119) · 36 |
| SPRT de Poisson | 5,50 | 0,88 · 0,009 | 96 % · 28 (53) · 10 | 100 % · 20 (27) · 4 | 100 % · 36 (76) · 16 | 100 % · 13 (51) · 0 | 3 % · 77 (287) · 45 |
| estático piso 3 | 3,00 | 1,08 · 0,011 | 15 % · 38 (129) · 24 | 53 % · 63 (498) · 20 | 49 % · 104 (542) · 34 | 78 % · 11 (59) · 0 | 1 % · 24 (74) · 28 |
| estático del diseño (piso 10, 3×p95; sin calibrar) | 3,00 | 0,00 · 0,000 | 2 % · 227 (484) · 58 | 22 % · 283 (744) · 29 | 19 % · 300 (800) · 41 | 77 % · 24 (91) · 7 | 0 % · ∞ (∞) · ∞ |

## E7 · Piso semanal de revisiones por patrón frente a uniforme puro

60 semillas, política combinada, clave fija. Piso = si un patrón activo lleva < k revisiones en la semana a partir del día 3 de la semana, se revisan sus alertas hasta cumplirlo.

_Datos sintéticos (simulador `research/soc-lab/src/sim2.ts`); no son cifras de producción._

| Muestreo | Revisiones/corrida | Cobertura % | (a) mayor volumen: TP atacante | (b) menor volumen: TP atacante |
|---|---:|---:|---:|---:|
| uniforme 10 % | 1768 | 41,9 [40,5; 43,3] | 28,9 [25,0; 32,5] | 20,2 [18,0; 22,3] |
| uniforme 10 % + piso 2/semana | 3094 | 39,7 [38,3; 41,1] | 26,9 [23,3; 30,4] | 6,2 [5,1; 7,3] |
| uniforme 8 % + piso 2/semana | 2937 | 40,7 [39,3; 42,1] | 29,3 [25,5; 33,1] | 6,6 [5,5; 7,8] |

## E8 · Sensibilidad (un factor a la vez desde los valores por defecto)

60 semillas por celda. Celda: cobertura % · TP suprimidos · TP del atacante (media). Δ = combinada − N=5 en TP suprimidos [IC 95 %].

_Datos sintéticos (simulador `research/soc-lab/src/sim2.ts`); no son cifras de producción._

| Factor | Valor | N=5 | Combinada | Δ TP suprimidos |
|---|---|---|---|---:|
| prevalencia del atacante (TP/día por patrón) | 0,25 | 69,6 · 81,3 · 13,2 | 43,5 · 32,1 · 13,6 | -49,2 [-58,5; -40,4] |
| prevalencia del atacante (TP/día por patrón) | 1,00 | 68,2 · 97,5 · 29,9 | 41,9 · 46,9 · 28,9 | -50,7 [-61,3; -40,8] |
| prevalencia del atacante (TP/día por patrón) | 4,00 | 66,9 · 96,1 · 28,7 | 40,6 · 44,9 · 27,4 | -51,2 [-61,6; -42,0] |
| escala de θ_TP (tasa de TP entre alertas) | ×0,5 | 70,7 · 77,2 · 28,6 | 43,9 · 44,6 · 27,8 | -32,5 [-40,0; -25,7] |
| escala de θ_TP (tasa de TP entre alertas) | ×1,0 | 68,2 · 97,5 · 29,9 | 41,9 · 46,9 · 28,9 | -50,7 [-61,3; -40,8] |
| escala de θ_TP (tasa de TP entre alertas) | ×2,0 | 64,9 · 112,4 · 27,9 | 39,1 · 47,2 · 27,0 | -65,2 [-75,7; -55,2] |
| asimetría de volúmenes (σ lognormal) | 0,5 | 79,4 · 92,9 · 26,0 | 43,4 · 37,4 · 25,6 | -55,5 [-65,6; -46,0] |
| asimetría de volúmenes (σ lognormal) | 1,0 | 68,2 · 97,5 · 29,9 | 41,9 · 46,9 · 28,9 | -50,7 [-61,3; -40,8] |
| asimetría de volúmenes (σ lognormal) | 1,5 | 46,9 · 89,1 · 22,4 | 32,9 · 49,6 · 26,0 | -39,5 [-49,9; -30,3] |

Tiempo total: 1863 s.
