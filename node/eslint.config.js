import chaiExpect from 'eslint-plugin-chai-expect';
import header from 'eslint-plugin-header';
import _import from 'eslint-plugin-import';
import jsdoc from 'eslint-plugin-jsdoc';
import mocha from 'eslint-plugin-mocha';
import tsEslint from 'typescript-eslint';
import { defineConfig } from 'eslint/config';
import eslintJs from '@eslint/js';
import promise from 'eslint-plugin-promise';

// Work around eslint 9 compatibility issue; see
// https://github.com/Stuk/eslint-plugin-header/issues/57
header.rules.header.meta.schema = false;

const config = defineConfig(
  eslintJs.configs.recommended,
  ...tsEslint.configs.recommendedTypeChecked,
  chaiExpect.configs['recommended-flat'],
  _import.flatConfigs.errors,
  _import.flatConfigs.warnings,
  _import.flatConfigs.typescript,
  {
    plugins: {
      eslintJs,
      header,
      jsdoc,
      mocha,
      promise,
    },

    rules: {
      'header/header': [
        2,
        'line',
        [
          '',
          {
            pattern: ' Copyright \\d{4}(-\\d{4})? Signal Messenger, LLC.',
          },
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

      'no-restricted-globals': [
        'error',
        {
          name: 'Buffer',
          message: 'Import from node:buffer instead.',
        },
      ],

      'mocha/no-exclusive-tests': 'error',
      'promise/prefer-await-to-then': 'error',
      'no-use-before-define': 'off',
      'no-underscore-dangle': 'off',

      '@typescript-eslint/no-unused-vars': [
        'error',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      '@typescript-eslint/no-non-null-assertion': 'error',

      '@typescript-eslint/no-redeclare': 'error',

      '@typescript-eslint/no-shadow': [
        'error',
        {
          ignoreOnInitialization: true,
        },
      ],

      '@typescript-eslint/no-useless-constructor': ['error'],
      'no-shadow': 'off',
      'no-useless-constructor': 'off',
      'no-console': 'error',
      'operator-linebreak': 'error',

      quotes: [
        'error',
        'single',
        {
          avoidEscape: true,
          allowTemplateLiterals: false,
        },
      ],

      'import/prefer-default-export': 'off',
      'import/enforce-node-protocol-usage': ['error', 'always'],
      'import/no-extraneous-dependencies': [
        'error',
        {
          devDependencies: ['ts/test/**'],
        },
      ],
      'prefer-template': 'error',
      '@typescript-eslint/no-require-imports': 'error',
      '@typescript-eslint/consistent-type-assertions': 'error',
      '@typescript-eslint/explicit-module-boundary-types': 'error',
      '@typescript-eslint/restrict-template-expressions': 'off',
      '@typescript-eslint/method-signature-style': 'error',
      'jsdoc/check-access': 'error',
      'jsdoc/check-alignment': 'error',
      'jsdoc/check-line-alignment': 'error',

      'jsdoc/check-param-names': [
        'error',
        {
          disableMissingParamChecks: true,
        },
      ],

      'jsdoc/check-property-names': 'error',
      'jsdoc/check-syntax': 'error',
      'jsdoc/check-tag-names': 'error',
      'jsdoc/check-types': 'error',
      'jsdoc/check-values': 'error',
      'jsdoc/empty-tags': 'error',
      'jsdoc/implements-on-classes': 'error',
      'jsdoc/multiline-blocks': 'error',
      'jsdoc/no-bad-blocks': 'error',
      'jsdoc/no-blank-blocks': 'error',
      'jsdoc/no-undefined-types': 'error',
      'jsdoc/valid-types': 'error',
    },
  }
)
  .map((config) => {
    return {
      ...config,
      languageOptions: {
        ...config.languageOptions,
        parserOptions: {
          project: 'tsconfig.json',
        },
      },
      settings: {
        ...config.settings,
        'import/core-modules': ['electron'],
        'import/resolver': {
          typescript: {
            project: 'tsconfig.json',
          },
        },
      },
    };
  })
  .concat([
    // Ignores in their own config object are treated as global.
    {
      ignores: [
        'build/**/*',
        'dist/**/*',
        '**/eslint.config.js',
        '**/Native.js',
        '**/zkgroup.js',
        '**/zkgroup.d.ts',
        'ts/node-gyp-build.d.ts',
      ],
    },
  ]);

export default config;
