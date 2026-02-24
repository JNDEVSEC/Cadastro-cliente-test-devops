// .eslintrc.cjs
module.exports = {
  root: true,
  env: { es2022: true, node: true, browser: false },
  parserOptions: { ecmaVersion: "latest", sourceType: "module" },
  plugins: ["security", "@microsoft/sdl"],
  extends: [
    "eslint:recommended",
    "plugin:security/recommended-legacy", // regras críticas do plugin security
    // Conjuntos recomendados do SDL:
    // "@microsoft/eslint-plugin-sdl/recommended",
    // "@microsoft/eslint-plugin-sdl/node",
  ],
  rules: {
    // Trate violações críticas como erro para bloquear merges:
    "no-eval": "error",
    "security/detect-child-process": "error",
    "security/detect-non-literal-require": "error",
    "security/detect-unsafe-regex": "error",
    "@microsoft/sdl/no-inner-html": "error",
    // Itens médios → warning (não bloqueia, mas alerta):
    "security/detect-object-injection": "warn",
  },
  ignorePatterns: ["dist/**", "build/**", "**/*.min.js"],
};

