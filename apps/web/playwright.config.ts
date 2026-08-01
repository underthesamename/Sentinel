import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  use: {
    baseURL: "http://127.0.0.1:5173",
    trace: "retain-on-failure",
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 5"] } },
  ],
  webServer: [
    {
      command: "cargo run -p sentinel-api",
      cwd: "../..",
      url: "http://127.0.0.1:8080/health/ready",
      reuseExistingServer: true,
      timeout: 120_000,
      env: {
        APP_ENV: "local",
        API_BIND: "127.0.0.1:8080",
        APP_ORIGIN: "http://127.0.0.1:5173",
        DATABASE_URL:
          process.env.TEST_DATABASE_URL ??
          "postgres://sentinel:sentinel@127.0.0.1:5432/sentinel",
        TOKEN_FINGERPRINT_KEYS:
          "e2e-v1:synthetic-e2e-key-with-at-least-32-bytes",
      },
    },
    {
      command: "npm run dev -- --host 127.0.0.1",
      url: "http://127.0.0.1:5173",
      reuseExistingServer: true,
    },
  ],
});
