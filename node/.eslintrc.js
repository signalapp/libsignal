// For reference: https://github.com/airbnb/javascript

module.exports = {
  root: true,

  parserOptions: {
    project: './tsconfig.json',
    ecmaVersion: 2018,
    sourceType: 'module',
  },

  settings: {
    'import/core-modules': ['electron'],
  },

  plugins: ['header', 'import', 'mocha', 'more', '@typescript-eslint'],

  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:import/errors',
    'plugin:import/warnings',
    'plugin:import/typescript',
  ],

  rules: {
    'header/header': [
      2,
      'line',
      [
        '',
        { pattern: ' Copyright \\d{4}(-\\d{4})? Signal Messenger, LLC.' },
        ' SPDX-License-Identifier: AGPL-3.0-only',
        '',
      ],
    ],

    'comma-dangle': [
      'error',
      {
        arrays: 'always-multiline',
        objects: 'always-multiline',
        imports: 'always-multiline',
        exports: 'always-multiline',
        functions: 'never',
      },
    ],

    // prevents us from accidentally checking in exclusive tests (`.only`):
    'mocha/no-exclusive-tests': 'error',

    // encourage consistent use of `async` / `await` instead of `then`
    'more/no-then': 'error',

    // it helps readability to put public API at top,
    'no-use-before-define': 'off',

    // useful for unused or internal fields
    'no-underscore-dangle': 'off',

    // useful for unused parameters
    '@typescript-eslint/no-unused-vars': [
      'error',
      { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
    ],

    // though we have a logger, we still remap console to log to disk
    'no-console': 'error',

    // consistently place operators at end of line except ternaries
    'operator-linebreak': 'error',

    quotes: [
      'error',
      'single',
      { avoidEscape: true, allowTemplateLiterals: false },
    ],

    // We prefer named exports
    'import/prefer-default-export': 'off',

    '@typescript-eslint/no-require-imports': 'error',
    '@typescript-eslint/consistent-type-assertions': 'error',
    '@typescript-eslint/explicit-module-boundary-types': 'error',
  },
};
