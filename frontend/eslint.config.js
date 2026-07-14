import js from "@eslint/js";

export default [
  { ignores: ["web/**", "node_modules/**"] },
  js.configs.recommended,
  {
    files: ["src/**/*.{js,jsx}"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: {
        AbortController: "readonly",
        cancelAnimationFrame: "readonly",
        Response: "readonly",
        IntersectionObserver: "readonly",
        performance: "readonly",
        requestAnimationFrame: "readonly",
        ResizeObserver: "readonly",
        document: "readonly",
        fetch: "readonly",
        localStorage: "readonly",
        location: "readonly",
        matchMedia: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        window: "readonly",
      },
    },
    rules: { "no-unused-vars": ["error", { argsIgnorePattern: "^_" }] },
  },
];
