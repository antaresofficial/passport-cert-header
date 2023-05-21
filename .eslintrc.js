module.exports = {
  env: {
    browser: true,
    commonjs: true,
    es2021: true,
  },
  extends: 'airbnb-base',
  overrides: [
  ],
  plugins: ['unused-imports'],
  parserOptions: {
    ecmaVersion: 'latest',
  },
  rules: {
    'sort-imports': [
      'error',
      {
        ignoreDeclarationSort: true,
      },
    ],
    'consistent-return': 'off',
    'no-console': 'off',
    'no-underscore-dangle': 'off',
    'no-multi-assign': 'off',
    'no-new': 'off',
    'func-names': 'off',
    'vars-on-top': 'off',
  },
};
