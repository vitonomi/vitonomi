// @ts-check
import importPlugin from 'eslint-plugin-import';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/.next/**',
      '**/coverage/**',
      '**/*.config.js',
      '**/*.config.mjs',
    ],
  },
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: { ...globals.node },
      parserOptions: {
        project: ['./tsconfig.eslint.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: {
      import: importPlugin,
    },
    rules: {
      // No `any`. Force `unknown` + narrowing.
      '@typescript-eslint/no-explicit-any': 'error',

      // No silent catch blocks (CLAUDE.md rule).
      'no-empty': ['error', { allowEmptyCatch: false }],

      // No console.log — use the structured logger from core/.
      'no-console': ['error', { allow: ['warn', 'error'] }],

      // No CommonJS.
      '@typescript-eslint/no-require-imports': 'error',

      // Named exports only.
      'import/no-default-export': 'error',
      'no-restricted-syntax': [
        'error',
        {
          selector: 'ExportDefaultDeclaration',
          message: 'Default exports are forbidden — use named exports.',
        },
      ],

      // Import order: builtins → third-party → local, alphabetical within groups.
      'import/order': [
        'error',
        {
          groups: ['builtin', 'external', 'internal', ['parent', 'sibling', 'index']],
          'newlines-between': 'always',
          alphabetize: { order: 'asc', caseInsensitive: true },
        },
      ],

      // Allow type-only unused vars prefixed with _.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' },
      ],
    },
  },
  // Tests: Vitest globals + relax a few strict rules that hurt readability.
  {
    files: ['**/tests/**/*.ts', '**/*.test.ts', '**/*.spec.ts'],
    languageOptions: {
      globals: { ...globals.node, ...globals.jest },
    },
    rules: {
      '@typescript-eslint/no-floating-promises': 'off',
      '@typescript-eslint/unbound-method': 'off',
    },
  },
  // Allow default exports in Next.js conventional files and Vitest config.
  {
    files: [
      'web/src/app/**/*.{ts,tsx}',
      'web/next.config.{js,ts,mjs}',
      'web/middleware.ts',
      '**/vitest.config.ts',
    ],
    rules: {
      'import/no-default-export': 'off',
      'no-restricted-syntax': 'off',
    },
  },
);
