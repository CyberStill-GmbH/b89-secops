import { defineConfig } from 'vitest/config';

// Laboratorio aislado: no entra en la suite del repo (vitest.config.ts raíz no incluye research/).
export default defineConfig({
  resolve: { conditions: ['development'] },
  test: {
    include: ['research/soc-lab/test/**/*.spec.ts'],
    testTimeout: 120_000,
  },
});
