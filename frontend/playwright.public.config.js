import { defineConfig } from "@playwright/test";

const baseURL = process.env.PUBLIC_BASE_URL;
if (!baseURL) {
  throw new Error("PUBLIC_BASE_URL is required for the public release gate");
}

export default defineConfig({
  testDir: "./e2e",
  testMatch: "public-release.spec.js",
  timeout: 45_000,
  use: {
    baseURL,
    trace: "retain-on-failure",
  },
});
