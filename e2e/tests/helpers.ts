import { Page } from '@playwright/test'

export const TEST_USER = {
  email: 'e2e@sentinel.test',
  password: 'e2epassword123',
  workspace: 'E2E Workspace',
}

export async function register(page: Page) {
  await page.goto('/login')
  // If login page has a Register link, use it; otherwise hit API directly
  const resp = await page.request.post('http://localhost:8000/auth/register', {
    data: {
      email: TEST_USER.email,
      password: TEST_USER.password,
      workspace_name: TEST_USER.workspace,
    },
  })
  return resp.ok()
}

export async function login(page: Page) {
  await page.goto('/login')
  await page.fill('input[type="email"], input[name="email"]', TEST_USER.email)
  await page.fill('input[type="password"]', TEST_USER.password)
  await page.click('button[type="submit"]')
  await page.waitForURL('**/')
}
