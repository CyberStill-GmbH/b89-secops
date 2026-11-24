import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: { conditions: ['development'] },
  test: {
    include: [
      'platform/**/test/**/*.spec.ts',
      'modules/**/test/**/*.spec.ts',
      'packages/**/test/**/*.spec.ts',
      'apps/**/test/**/*.spec.ts',
      'apps/**/test/**/*.spec.tsx',
      'tests/architecture/**/*.spec.ts',
    ],
    exclude: ['**/node_modules/**', '**/dist/**', '**/*.integration.spec.ts'],
    passWithNoTests: false,
    fsModuleCache: true,
    isolate: false,
    // Concurrencia acotada: varias specs levantan Nest completo, derivan scrypt o recorren el
    // repo. Con un worker por núcleo se ralentizaban 5–10× y vencían el timeout de 5 s sin fallar
    // en lógica (3 de 5 corridas rojas, medido 2026-11-24). La mitad de los núcleos deja margen
    // al proceso principal y a otros procesos de la máquina o del runner.
    maxWorkers: '50%',
  },
});
