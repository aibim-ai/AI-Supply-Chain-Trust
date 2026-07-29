import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { configDefaults } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  base: "/",
  test: {
    exclude: [...configDefaults.exclude, "e2e/**"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.{js,jsx}"],
      exclude: ["src/main.jsx"],
      reporter: ["text", "lcov"],
      thresholds: {
        statements: 75,
        branches: 60,
        functions: 75,
        lines: 80,
      },
    },
  },
  build: {
    outDir: "web",
    // Keep the previous release's lazy chunks as a short-lived compatibility
    // set. Browsers or edge caches holding the old app.js can still finish a
    // navigation while the new single-bundle release rolls out.
    emptyOutDir: false,
    rollupOptions: {
      output: {
        entryFileNames: "assets/js/app.js",
        assetFileNames: (a) =>
          a.name?.endsWith(".css")
            ? "assets/css/design-system.css"
            : "assets/[name][extname]",
        chunkFileNames: "assets/js/[name].js",
      },
    },
  },
});
