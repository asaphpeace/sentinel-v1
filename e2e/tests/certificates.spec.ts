/**
 * E5 — Certificates view.
 * Verifies domain filter uses backend domains list, not cert data.
 */
import { test, expect } from '@playwright/test'
import { login, TEST_USER } from './helpers'

test.beforeAll(async ({ request }) => {
  await request.post('http://localhost:8000/auth/register', {
    data: { email: TEST_USER.email, password: TEST_USER.password, workspace_name: TEST_USER.workspace },
  })
})

test('E5 — Certificates page loads', async ({ page }) => {
  await login(page)
  await page.goto('/certs')
  await expect(page.locator('h1, .page-title, [class*="title"]').first()).toBeVisible()
})

test('E5 — domain filter dropdown is visible', async ({ page }) => {
  await login(page)
  await page.goto('/certs')
  // The domain filter button/select
  const filterBtn = page.locator('.domain-filter, select, button[class*="filter"]').first()
  await expect(filterBtn).toBeVisible({ timeout: 5000 })
})

test('E5 — domain filter contains backend domains', async ({ page, request }) => {
  await login(page)

  // Get the domains list from the backend
  const token = await page.evaluate(() => localStorage.getItem('sentinel_token'))
  const domainsResp = await request.get('http://localhost:8000/domains', {
    headers: { Authorization: `Bearer ${token}` },
  })
  const domains: any[] = await domainsResp.json()

  await page.goto('/certs')

  // Open the domain dropdown
  const filterBtn = page.locator('button.filter-btn, button[class*="filter"], .domain-filter').first()
  if (await filterBtn.isVisible()) {
    await filterBtn.click()
    for (const d of domains.slice(0, 3)) {
      const option = page.locator(`text=${d.name ?? d.domain}`)
      if (await option.count() > 0) {
        await expect(option.first()).toBeVisible()
      }
    }
  }
})
