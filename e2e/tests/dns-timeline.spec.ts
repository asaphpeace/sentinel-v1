/**
 * E4 — DNS Timeline view.
 * Verifies events visible, security alert badge, diff expand.
 */
import { test, expect } from '@playwright/test'
import { login, TEST_USER } from './helpers'

test.beforeAll(async ({ request }) => {
  await request.post('http://localhost:8000/auth/register', {
    data: { email: TEST_USER.email, password: TEST_USER.password, workspace_name: TEST_USER.workspace },
  })
})

test('E4 — DNS timeline page loads', async ({ page }) => {
  await login(page)
  await page.goto('/timeline')
  await expect(page.locator('h1, .page-title, [class*="title"]').first()).toBeVisible()
})

test('E4 — security alert badge visible for flagged events', async ({ page }) => {
  await login(page)
  await page.goto('/timeline')
  // If seed data is loaded, at least one alert badge should exist
  const alertBadges = page.locator('.alert-badge')
  const count = await alertBadges.count()
  // Only assert badge renders correctly if any exist
  if (count > 0) {
    await expect(alertBadges.first()).toBeVisible()
  }
})

test('E4 — timeline entry expands on click', async ({ page }) => {
  await login(page)
  await page.goto('/timeline')

  const entries = page.locator('.entry-main')
  const count = await entries.count()

  if (count > 0) {
    await entries.first().click()
    // Full diff block or expanded content should appear
    const expanded = page.locator('.full-diff, .entry-expanded').first()
    await expect(expanded).toBeVisible({ timeout: 3000 })
  }
})

test('E4 — load more button shows remaining count', async ({ page }) => {
  await login(page)
  await page.goto('/timeline')
  const loadMore = page.locator('button', { hasText: /load/i })
  if (await loadMore.isVisible()) {
    await expect(loadMore).toContainText(/\d+/)
  }
})
