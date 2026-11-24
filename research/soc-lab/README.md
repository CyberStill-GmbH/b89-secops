# Laboratorio del SOC que aprende (F2)

Prototipos **aislados de producción** de las fichas 1, 2, 3, 4 y 6 de
`docs/soc-learning/20-innovacion-tecnica.md`. Nada de aquí lo importa el código de producción;
el laboratorio solo **lee** la huella real (`modules/detection/src/fingerprint.ts`) para los
canarios y las propiedades de la huella. Datos 100 % sintéticos, sin secretos.

| Archivo | Qué contiene |
|---|---|
| `src/rng.ts` | Generador con semilla (mulberry32), Poisson, Gamma, Beta |
| `src/stats.ts` | Beta incompleta regularizada, cuantil, cota Clopper–Pearson exacta |
| `src/sim.ts` | Mundo (reglas, patrones, θ_TP), analistas con error, atacante mimético, envenenamiento; políticas de conteo (línea base), Clopper–Pearson (ficha 1) y jerárquica (ficha 3); muestreo uniforme y adaptativo (ficha 2) |
| `src/sampling.ts` | PRF con clave (HMAC-SHA256) y estimador de razón de Horvitz–Thompson |
| `src/drift.ts` | CUSUM de Poisson frente al multiplicador estático, con umbral calibrado (ficha 6) |
| `src/canary.ts` | Canarios de casi-coincidencia contra la huella real y un modelo de la decisión del diseño §7 (ficha 4) |
| `test/properties.spec.ts` | Pruebas basadas en propiedades (1000 repeticiones, semillas fijas) |
| `run-all.ts` | Corre todo y escribe `RESULTS.md` y `out/*.csv` |

```powershell
pnpm exec tsx --conditions=development research/soc-lab/run-all.ts
```

```powershell
pnpm exec vitest run --config research/soc-lab/vitest.config.ts
```

Modelo del mundo (supuestos explícitos, todos ajustables en `src/sim.ts`):
- 30 reglas: 70 % «limpias» (θ = 0 en el 90 % de sus patrones, si no ~0,1 %), 20 % «bajas»
  (θ ~ Beta(2, 398) ≈ 0,5 %) y 10 % «riesgosas» (θ ~ Beta(2, 38) ≈ 5 %).
- 1 + Poisson(3) patrones por regla, con tasa lognormal de mediana 1,2 alertas/día.
- El analista se equivoca: etiqueta FP un TP real el 2 % de las veces y TP un FP real el 0,5 %.
- Solo las etiquetas humanas son evidencia (los autocierres no cuentan: etapa A).
- Una revisión que encuentra un TP **pausa** el patrón.
- Atacante: desde el día 90 copia **exactamente** la huella de los 3 patrones activos de más
  volumen e inyecta ~1 TP/día en cada uno durante 30 días. Es el peor caso: la huella no lo
  distingue.

Límites conocidos:
- No hay datos reales; los números sirven para comparar políticas entre sí.
- La decisión de los canarios es un modelo del diseño, no el motor (que no existe).
- La política jerárquica usa un empírico-Bayes simple (momentos con prior global 1 %), no un
  ajuste por máxima verosimilitud.
