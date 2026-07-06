/**
 * E3 — Report wizard + report page.
 */
import { test, expect } from '@playwright/test'
import { login, TEST_USER } from './helpers'

test.beforeAll(async ({ request }) => {
  await request.post('http://localhost:8000/auth/register', {
    data: { email: TEST_USER.email, password: TEST_USER.password, workspace_name: TEST_USER.workspace },
  })
})

test('E3 — Generate report button opens wizard', async ({ page }) => {
  await login(page)
  await page.click('button.report-btn')
  await expect(page.locator('.wizard')).toBeVisible()
  await expect(page.locator('.wiz-title')).toContainText('Report scope')
})

test('E3 — Wizard step 1 → step 2 navigation', async ({ page }) => {
  await login(page)
  await page.click('button.report-btn')
  await page.click('button.btn-primary')  // Continue
  await expect(page.locator('.wiz-title')).toContainText('Review & generate')
})

test('E3 — Report opens in new tab', async ({ page, context }) => {
  await login(page)
  await page.click('button.report-btn')
  await page.click('button.btn-primary')  // Continue to step 2

  const [reportTab] = await Promise.all([
    context.waitForEvent('page'),
    page.click('button.btn-primary'),     // Generate
  ])

  await reportTab.waitForLoadState('domcontentloaded')
  expect(reportTab.url()).toContain('/report')
})

test('E3 — Report page renders workspace name', async ({ page, context }) => {
  await login(page)
  await page.click('button.report-btn')
  await page.click('button.btn-primary')

  const [reportTab] = await Promise.all([
    context.waitForEvent('page'),
    page.click('button.btn-primary'),
  ])

  await reportTab.waitForSelector('.cover-workspace', { timeout: 10_000 })
  await expect(reportTab.locator('.cover-workspace')).toContainText(TEST_USER.workspace)
})

test('E3 — Report wizard closes after generate', async ({ page, context }) => {
  await login(page)
  await page.click('button.report-btn')
  await page.click('button.btn-primary')

  const [_tab] = await Promise.all([
    context.waitForEvent('page'),
    page.click('button.btn-primary'),
  ])

  // Wizard should be gone from the original page
  await expect(page.locator('.wizard')).not.toBeVisible()
})
