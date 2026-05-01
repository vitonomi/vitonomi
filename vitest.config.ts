import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: [
      '{core,cli,vault,hub,mx}/tests/**/*.test.ts',
      'clients/web/tests/**/*.test.ts',
      '{core,cli,vault,hub,mx}/src/**/*.test.ts',
      'clients/web/src/**/*.test.ts',
    ],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['{core,cli,vault,hub,mx}/src/**/*.ts', 'clients/web/src/**/*.ts'],
      exclude: ['**/*.d.ts', '**/index.ts'],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 75,
        statements: 80,
      },
    },
  },
});
