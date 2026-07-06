/**
 * F5 — TimelineEntry component tests.
 * Verifies icon, security badge, diff tokens, and expand behaviour.
 */
import { describe, it, expect } from 'vitest'
import { mount } from '@vue/test-utils'
import TimelineEntry from '@/components/ui/TimelineEntry.vue'

function makeEntry(overrides = {}) {
  return {
    id: '1',
    domain_id: 'd1',
    domain_name: 'example.com',
    record_type: 'DMARC',
    record_host: '_dmarc.example.com',
    previous_value: null,
    current_value: 'v=DMARC1; p=reject',
    change_summary: null,
    change_type: 'added',
    is_security_alert: false,
    detected_at: new Date().toISOString(),
    ...overrides,
  }
}

describe('TimelineEntry', () => {

  describe('change-type icon', () => {
    it('renders + icon for added', () => {
      const w = mount(TimelineEntry, { props: { entry: makeEntry({ change_type: 'added' }) } })
      expect(w.text()).toContain('+')
    })

    it('renders ~ icon for modified', () => {
      const w = mount(TimelineEntry, {
        props: {
          entry: makeEntry({
            change_type: 'modified',
            previous_value: 'v=DMARC1; p=none',
            current_value: 'v=DMARC1; p=reject',
          }),
        },
      })
      expect(w.text()).toContain('~')
    })

    it('renders − icon for removed', () => {
      const w = mount(TimelineEntry, {
        props: {
          entry: makeEntry({
            change_type: 'removed',
            current_value: null,
            previous_value: 'v=DMARC1; p=reject',
          }),
        },
      })
      expect(w.text()).toContain('−')
    })
  })

  describe('security alert badge', () => {
    it('shows alert flag when is_security_alert is true', () => {
      const w = mount(TimelineEntry, {
        props: {
          entry: makeEntry({
            is_security_alert: true,
            change_type: 'modified',
            previous_value: 'v=DMARC1; p=reject',
            current_value: 'v=DMARC1; p=none',
          }),
        },
      })
      expect(w.find('.alert-flag').exists()).toBe(true)
    })

    it('hides alert flag when is_security_alert is false', () => {
      const w = mount(TimelineEntry, { props: { entry: makeEntry() } })
      expect(w.find('.alert-flag').exists()).toBe(false)
    })

    it('entry has alert css class when is_security_alert is true', () => {
      const w = mount(TimelineEntry, {
        props: { entry: makeEntry({ is_security_alert: true }) },
      })
      expect(w.find('.entry.alert').exists()).toBe(true)
    })
  })

  describe('diff tokens (modified entries)', () => {
    it('shows inline diff tokens for modified entries', () => {
      const w = mount(TimelineEntry, {
        props: {
          entry: makeEntry({
            change_type: 'modified',
            previous_value: 'v=DMARC1; p=none',
            current_value: 'v=DMARC1; p=reject',
          }),
        },
      })
      // Mini diff tokens visible before expanding
      expect(w.find('.mini-diff').exists()).toBe(true)
    })

    it('removed token has "removed" class', () => {
      const w = mount(TimelineEntry, {
        props: {
          entry: makeEntry({
            change_type: 'modified',
            previous_value: 'v=DMARC1; p=none',
            current_value: 'v=DMARC1; p=reject',
          }),
        },
      })
      expect(w.find('.diff-token.removed').exists()).toBe(true)
    })

    it('does not show mini-diff for added entries (no previous)', () => {
      const w = mount(TimelineEntry, {
        props: {
          entry: makeEntry({ change_type: 'added', previous_value: null }),
        },
      })
      expect(w.find('.mini-diff').exists()).toBe(false)
    })
  })

  describe('expand / collapse', () => {
    it('diff-block is hidden by default', () => {
      const w = mount(TimelineEntry, {
        props: {
          entry: makeEntry({
            change_type: 'modified',
            previous_value: 'v=DMARC1; p=none',
            current_value: 'v=DMARC1; p=reject',
          }),
        },
      })
      expect(w.find('.diff-block').exists()).toBe(false)
    })

    it('diff-block appears after clicking body', async () => {
      const w = mount(TimelineEntry, {
        props: {
          entry: makeEntry({
            change_type: 'modified',
            previous_value: 'v=DMARC1; p=none',
            current_value: 'v=DMARC1; p=reject',
          }),
        },
      })
      await w.find('.body').trigger('click')
      expect(w.find('.diff-block').exists()).toBe(true)
    })

    it('collapses on second click', async () => {
      const w = mount(TimelineEntry, {
        props: {
          entry: makeEntry({
            change_type: 'modified',
            previous_value: 'old',
            current_value: 'new',
          }),
        },
      })
      await w.find('.body').trigger('click')
      await w.find('.body').trigger('click')
      expect(w.find('.diff-block').exists()).toBe(false)
    })
  })

  describe('relative time', () => {
    it('shows "Just now" for very recent entries', () => {
      const w = mount(TimelineEntry, {
        props: { entry: makeEntry({ detected_at: new Date().toISOString() }) },
      })
      expect(w.text()).toContain('Just now')
    })
  })
})
