/**
 * F4 — ReportWizard component tests.
 * Verifies step navigation, canProceed gate, and URL generation.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createRouter, createWebHashHistory } from 'vue-router'
import ReportWizard from '@/components/ui/ReportWizard.vue'
import { useDomainsStore } from '@/stores/domains'

// Minimal router so vue-router composables work
const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: '/', component: { template: '<div/>' } },
    { path: '/report', name: 'report', component: { template: '<div/>' } },
  ],
})

function mountWizard() {
  return mount(ReportWizard, {
    global: {
      plugins: [createPinia(), router],
      stubs: { Teleport: true },  // Teleport renders inline in tests
    },
  })
}

describe('ReportWizard', () => {

  describe('Step 1 — scope selection', () => {
    it('starts on step 1', () => {
      const w = mountWizard()
      expect(w.text()).toContain('Report scope')
    })

    it('shows Continue button on step 1', () => {
      const w = mountWizard()
      expect(w.find('button.btn-primary').text()).toMatch(/continue/i)
    })

    it('Continue is disabled when subset selected but no domains checked', async () => {
      const w = mountWizard()
      // Click "Select specific domains"
      const subsetBtn = w.findAll('button.option-btn').find(b => b.text().includes('Select specific'))
      await subsetBtn?.trigger('click')

      const continueBtn = w.find('button.btn-primary')
      expect(continueBtn.attributes('disabled')).toBeDefined()
    })

    it('Continue is enabled when "All domains" is selected (default)', () => {
      const w = mountWizard()
      const continueBtn = w.find('button.btn-primary')
      expect(continueBtn.attributes('disabled')).toBeUndefined()
    })
  })

  describe('Step 2 — review', () => {
    async function goToStep2(w: ReturnType<typeof mountWizard>) {
      await w.find('button.btn-primary').trigger('click')
      await flushPromises()
    }

    it('advances to step 2 on Continue click', async () => {
      const w = mountWizard()
      await goToStep2(w)
      expect(w.text()).toContain('Review & generate')
    })

    it('shows Generate report button on step 2', async () => {
      const w = mountWizard()
      await goToStep2(w)
      expect(w.find('button.btn-primary').text()).toMatch(/generate report/i)
    })

    it('Back button returns to step 1', async () => {
      const w = mountWizard()
      await goToStep2(w)
      await w.find('button.btn-ghost').trigger('click')
      expect(w.text()).toContain('Report scope')
    })

    it('shows review summary with selected period', async () => {
      const w = mountWizard()
      // Select 90 days
      const btn90 = w.findAll('button.option-btn').find(b => b.text().includes('90'))
      await btn90?.trigger('click')
      await goToStep2(w)
      expect(w.text()).toContain('90')
    })
  })

  describe('generate()', () => {
    it('opens new tab with correct period query param', async () => {
      const openSpy = vi.spyOn(window, 'open').mockImplementation(() => null)

      const w = mountWizard()
      // Go to step 2 with default 30-day period
      await w.find('button.btn-primary').trigger('click')
      await flushPromises()
      // Click Generate
      await w.find('button.btn-primary').trigger('click')
      await flushPromises()

      expect(openSpy).toHaveBeenCalled()
      const url = openSpy.mock.calls[0][0] as string
      expect(url).toContain('period=30')
      openSpy.mockRestore()
    })

    it('emits close after generate', async () => {
      vi.spyOn(window, 'open').mockImplementation(() => null)

      const w = mountWizard()
      await w.find('button.btn-primary').trigger('click')
      await flushPromises()
      await w.find('button.btn-primary').trigger('click')
      await flushPromises()

      expect(w.emitted('close')).toBeTruthy()
    })

    it('close button emits close event', async () => {
      const w = mountWizard()
      await w.find('button.close-btn').trigger('click')
      expect(w.emitted('close')).toBeTruthy()
    })
  })
})
