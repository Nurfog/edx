module.exports = {
  extends: '@edx/eslint-config',
  root: true,
  settings: {
    'import/resolver': {
      webpack: {
        config: 'webpack.dev.config.js',
      },
    },
  },
  rules: {
    'func-names': 'off',
    indent: ['error', 4],
    'new-cap': 'off',
    'no-else-return': 'off',
    'no-shadow': 'error',
    'object-curly-spacing': ['error', 'never'],
    'one-var': 'off',
    'one-var-declaration-per-line': ['error', 'initializations'],
    'space-before-function-paren': ['error', 'never'],
    strict: 'off',

    // Temporary Rules (Will be removed one-by-one to minimize file changes)
    'block-scoped-var': 'off',
    camelcase: 'off',
    'comma-dangle': 'off',
    'consistent-return': 'off',
    curly: 'off',
    eqeqeq: 'off',
    'function-call-argument-newline': 'off',
    'function-paren-newline': 'off',
    'implicit-arrow-linebreak': 'off',
    'import/extensions': 'off',
    'import/no-amd': 'off',
    'import/no-dynamic-require': 'off',
    'import/no-unresolved': 'off',
    'linebreak-style': 'off',
    'lines-around-directive': 'off',
    'max-len': 'off',
    'newline-per-chained-call': 'off',
    'no-console': 'off',
    'no-lonely-if': 'off',
    'no-multi-spaces': 'off',
    'no-multiple-empty-lines': 'off',
    'no-param-reassign': 'off',
    'no-proto': 'off',
    'no-prototype-builtins': 'off',
    'no-redeclare': 'off',
    'no-restricted-globals': 'off',
    'no-restricted-syntax': 'off',
    'no-throw-literal': 'off',
    'no-undef': 'off',
    'no-underscore-dangle': 'off',
    'no-unused-vars': 'off',
    'no-use-before-define': 'off',
    'no-useless-escape': 'off',
    'no-var': 'off',
    'object-curly-newline': 'off',
    'object-shorthand': 'off',
    'operator-linebreak': 'off',
    'prefer-arrow-callback': 'off',
    'prefer-destructuring': 'off',
    'prefer-rest-params': 'off',
    'prefer-template': 'off',
    radix: 'off',
    quotes: 'off',
    'react/jsx-indent': 'off',
    'react/jsx-indent-props': 'off',
    'react/jsx-wrap-multilines': 'off',
    'react/prop-types': 'off',
    semi: 'off',
    'vars-on-top': 'off'
  },
};
