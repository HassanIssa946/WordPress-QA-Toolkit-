// ESLint flat config used by the toolkit (passed programmatically; the project's own config is not required).
export async function eslintConfig() {
  const js = (await import('@eslint/js')).default;
  const globals = (await import('globals')).default;
  const noUnsanitized = (await import('eslint-plugin-no-unsanitized')).default;
  return [
    { ignores: ['**/node_modules/**', '**/vendor/**', '**/build/**', '**/dist/**', '**/*.min.js'] },
    {
      files: ['**/*.{js,mjs,cjs,jsx}'],
      languageOptions: {
        ecmaVersion: 'latest',
        sourceType: 'module',
        parserOptions: { ecmaFeatures: { jsx: true } },
        globals: { ...globals.browser, ...globals.jquery, wp: 'readonly', ajaxurl: 'readonly', wpApiSettings: 'readonly' },
      },
      plugins: { 'no-unsanitized': noUnsanitized },
      rules: {
        ...js.configs.recommended.rules,
        'no-unused-vars': 'warn',
        'no-eval': 'error',
        'no-implied-eval': 'error',
        'no-new-func': 'error',
        'no-unsanitized/method': 'error',
        'no-unsanitized/property': 'error',
      },
    },
    { files: ['**/*.cjs', '**/webpack.config.js', '**/gulpfile.js'], languageOptions: { sourceType: 'commonjs', globals: { ...globals.node } } },
  ];
}
