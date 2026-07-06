import { defineConfig, devices } from '@playwright/test'

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,    // tests share a running backend — keep sequential
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  timeout: 30_000,
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
  // Start both servers before running tests
  webServer: [
    {
      command: 'cd ../backend && .venv\\Scripts\\uvicorn app.main:app --port 8000',
      url: 'http://localhost:8000/health',
      reuseExistingServer: !process.env.CI,
      timeout: 20_000,
    },
    {
      command: 'cd ../frontend && npm run dev',
      url: 'http://localhost:5173',
      reuseExistingServer: !process.env.CI,
      timeout: 20_000,
    },
  ],
})
