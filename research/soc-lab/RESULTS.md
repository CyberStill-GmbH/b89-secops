# Resultados F2 · laboratorio del SOC que aprende

Generado por `research/soc-lab/run-all.ts` · 30 semillas (1000–1029) · 180 días por corrida · números aleatorios comunes entre políticas.
Intervalos: media ± IC 95 % (1,96·σ/√n) sobre las semillas. Todo es **sintético**: muestra órdenes de magnitud y comparaciones relativas, no cifras de producción.

## E1 · Fichas 1 y 3 — riesgo frente a cobertura de autocierre

Muestreo uniforme del 10 % en todas. «TP suprimidos» = TP reales autocerrados y no detectados por la revisión (naturales + del atacante). «Inseguros activos» = patrones activos al final con θ_TP > 3 %.

| Política | Cobertura (%) | TP suprimidos / corrida | TP suprimidos por 10 000 autocierres | Del atacante | Inseguros activos |
|---|---:|---:|---:|---:|---:|
| conteo N=3 | 68.3 ± 2.4 | 98.9 ± 14.9 | 35.2 ± 6.0 | 25.7 ± 5.1 | 2.63 ± 0.67 |
| conteo N=5 | 66.9 ± 2.3 | 93.2 ± 13.1 | 33.8 ± 5.4 | 25.7 ± 5.1 | 2.43 ± 0.59 |
| conteo N=10 | 63.3 ± 2.5 | 77.6 ± 10.3 | 29.9 ± 4.6 | 25.6 ± 5.3 | 1.77 ± 0.37 |
| conteo N=20 | 57.5 ± 2.4 | 64.2 ± 9.2 | 27.3 ± 4.7 | 25.9 ± 5.1 | 1.00 ± 0.21 |
| conteo N=40 | 47.3 ± 2.3 | 49.9 ± 7.0 | 25.5 ± 4.0 | 26.9 ± 5.8 | 0.30 ± 0.17 |
| CP q=0.9 | 63.3 ± 2.1 | 83.9 ± 12.7 | 32.1 ± 5.3 | 23.7 ± 5.2 | 2.23 ± 0.62 |
| CP q=0.95 | 53.7 ± 1.9 | 54.4 ± 7.9 | 24.4 ± 3.8 | 23.7 ± 5.1 | 0.27 ± 0.16 |
| CP q=0.97 | 42.1 ± 1.7 | 40.6 ± 7.3 | 23.2 ± 4.4 | 23.6 ± 5.2 | 0.03 ± 0.07 |
| CP q=0.99 | 8.5 ± 0.9 | 25.1 ± 5.5 | 74.7 ± 19.7 | 24.1 ± 5.6 | 0.00 ± 0.00 |
| jerárquica q=0.9 | 69.2 ± 2.2 | 105.7 ± 16.1 | 37.1 ± 6.4 | 24.7 ± 5.2 | 2.93 ± 0.70 |
| jerárquica q=0.95 | 67.3 ± 2.3 | 79.1 ± 9.8 | 28.5 ± 4.1 | 24.7 ± 5.2 | 1.33 ± 0.37 |
| jerárquica q=0.97 | 64.8 ± 2.5 | 61.9 ± 8.4 | 23.1 ± 3.6 | 24.7 ± 5.2 | 0.67 ± 0.29 |
| jerárquica q=0.99 | 38.1 ± 2.3 | 32.6 ± 6.0 | 20.4 ± 3.7 | 23.0 ± 5.1 | 0.03 ± 0.07 |

## E1b · Ficha 3 — robustez ante envenenamiento

Una cuenta de analista comprometida etiqueta FP el 50 % de lo que revisa en una regla **riesgosa** (θ ≈ 5 %) durante 60 días.

| Política | TP suprimidos sin veneno | TP suprimidos con veneno | Inseguros activos sin / con veneno |
|---|---:|---:|---:|
| conteo N=5 | 93.2 ± 13.1 | 99.7 ± 13.4 | 2.43 / 2.53 |
| CP q=0.97 | 40.6 ± 7.3 | 42.0 ± 7.6 | 0.03 / 0.10 |
| jerárquica q=0.97 | 61.9 ± 8.4 | 68.9 ± 9.5 | 0.67 / 0.90 |

## E2 · Ficha 2 — muestreo de revisión con el mismo presupuesto

Atacante: copia exacta de los 3 patrones activos de más volumen desde el día 90, ~1 TP/día cada uno, 30 días. «Días hasta pausar» = mediana sobre patrones atacados (∞ = nunca). Sesgo y RMSE de Horvitz–Thompson frente a la precisión real de lo autocerrado.

| Política | Muestreo | Revisiones / corrida | Ataque suprimido | Días hasta pausar (mediana) | TP suprimidos totales | Sesgo HT (pp) | RMSE HT (pp) |
|---|---|---:|---:|---:|---:|---:|---:|
| conteo N=5 | sin muestreo | 0 ± 0 | 92.5 ± 3.3 | ∞ | 236.3 ± 29.6 | — | — |
| conteo N=5 | uniforme 10 % | 2791 ± 108 | 25.7 ± 5.1 | 7 | 93.2 ± 13.1 | -0.466 | 0.495 |
| conteo N=5 | adaptativo 10 % (piso 2 %) | 2996 ± 126 | 50.0 ± 6.8 | 17 | 115.9 ± 12.9 | -0.454 | 0.492 |
| CP q=0.97 | sin muestreo | 0 ± 0 | 92.5 ± 3.3 | ∞ | 125.3 ± 6.3 | — | — |
| CP q=0.97 | uniforme 10 % | 1765 ± 102 | 23.6 ± 5.2 | 5 | 40.6 ± 7.3 | -0.485 | 0.528 |
| CP q=0.97 | adaptativo 10 % (piso 2 %) | 1817 ± 109 | 32.1 ± 6.1 | 7 | 49.7 ± 8.0 | -0.476 | 0.526 |

## E3 · Ficha 6 — deriva de la tasa de un patrón

Tasa base 0,5 alertas/h con ciclo diario; cambio en la hora 360; 300 series de 30 días por escenario. Estático = alarma si una hora supera max(10, 3 × p95 base). CUSUM de Poisson (λ₁ = 2λ₀) con h = 6.60, calibrado en semillas distintas para ≤ 0.10 falsas alarmas/mes (el estático da 0.00).

| Escenario | Detector | Detecta (%) | Retraso mediano (h) | Falsas alarmas / mes |
|---|---|---:|---:|---:|
| sin cambio | estático 3×p95 | — | — | 0.00 |
| sin cambio | CUSUM h=6.60 | — | — | 0.07 |
| escalón ×2 | estático 3×p95 | 0 | ∞ | 0.00 |
| escalón ×2 | CUSUM h=6.60 | 100 | 29 | 0.08 |
| escalón ×3 | estático 3×p95 | 0 | ∞ | 0.00 |
| escalón ×3 | CUSUM h=6.60 | 100 | 11 | 0.08 |
| rampa a ×3 en 72 h | estático 3×p95 | 1 | ∞ | 0.00 |
| rampa a ×3 en 72 h | CUSUM h=6.60 | 100 | 49 | 0.08 |
| ráfaga legítima ×5 durante 2 h | estático 3×p95 | — | — | 0.00 |
| ráfaga legítima ×5 durante 2 h | CUSUM h=6.60 | — | — | 0.09 |

## E4 · Ficha 4 — canarios de casi-coincidencia · MODELO DE DISEÑO (no es evidencia del motor; contrato real en docs/soc-learning/16-contrato-canarios-motor.md)

500 patrones aprobados; por cada uno, una variante. La huella es la del repo (`modules/detection/src/fingerprint.ts`); la decisión es un **modelo** del diseño §7 (el motor no existe).

| Variante | Inyectados | Autocerrados | Escalados |
|---|---:|---:|---:|
| copia exacta | 500 | 478 | 22 |
| otro hash | 500 | 0 | 500 |
| otro destino | 500 | 0 | 500 |
| otro puerto | 500 | 0 | 500 |
| otro usuario | 500 | 0 | 500 |
| otro equipo | 500 | 0 | 500 |
| otro proceso padre | 500 | 0 | 500 |
| otra línea de comando | 500 | 0 | 500 |
| misma huella, prioridad P2 | 500 | 0 | 500 |
| misma huella, activo crítico | 500 | 0 | 500 |
| misma huella, identidad privilegiada | 500 | 0 | 500 |

Tiempo total: 178 s.
