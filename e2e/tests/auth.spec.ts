/**
 * E1 + E2 — Auth flows.
 * Tests login → sidebar workspace name, logout redirect, sign-out from profile.
 */
import { test, expect } from '@playwright/test'
import { register, login, TEST_USER } from './helpers'

test.beforeAll(async ({ request }) => {
  // Ensure test user exists (idempotent — 400 if already registered is fine)
  await request.post('http://localhost:8000/auth/register', {
    data: {
      email: TEST_USER.email,
      password: TEST_USER.password,
      workspace_name: TEST_USER.workspace,
    },
  })
})

test('E1 — workspace name appears in sidebar after login', async ({ page }) => {
  await login(page)
  // Sidebar user footer must contain the workspace name
  await expect(page.locator('.ws')).toContainText(TEST_USER.workspace)
})

test('E1 — workspace name does not overflow sidebar', async ({ page }) => {
  await login(page)
  const ws = page.locator('.ws')
  await expect(ws).toBeVisible()
  // Text should be truncated (overflow hidden / ellipsis) — not wider than sidebar
  const box = await ws.boundingBox()
  expect(box).not.toBeNull()
  expect(box!.width).toBeLessThanOrEqual(240)
})

test('E2 — sidebar logout redirects to /login', async ({ page }) => {
  await login(page)
  await page.click('.logout-btn')
  await expect(page).toHaveURL(/\/login/)
})

test('E2 — after logout, token is cleared (protected route redirects)', async ({ page }) => {
  await login(page)
  await page.click('.logout-btn')
  await page.goto('/')
  await expect(page).toHaveURL(/\/login/)
})

test('E2 — Profile sign-out button redirects to /login', async ({ page }) => {
  await login(page)
  await page.goto('/profile')
  // Find the sign-out button on the profile page
  const signOutBtn = page.getByRole('button', { name: /sign out/i })
  await signOutBtn.click()
  await expect(page).toHaveURL(/\/login/)
})
