import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts', 'test/**/*.test.tsx'],
    // PGlite / Miniflare (D1) databases are slow to start and query.
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
})
