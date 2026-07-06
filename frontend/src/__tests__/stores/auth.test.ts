/**
 * F1 — Auth store unit tests.
 *
 * vi.mock is hoisted to the top of the file by Vitest, so its factory
 * must be self-contained (no imported references). After the mock is set up
 * we use vi.mocked() to get typed handles on the injected fns.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useAuthStore } from '@/stores/auth'
import * as client from '@/api/client'

vi.mock('@/api/client', () => ({
  api: {
    login: vi.fn(), register: vi.fn(), overview: vi.fn(), threatSurface: vi.fn(),
    allCerts: vi.fn(), reportData: vi.fn(), domains: vi.fn(), domain: vi.fn(),
    deleteDomain: vi.fn(), syncDomainDns: vi.fn(), wizardStart: vi.fn(),
    wizardTlsInfo: vi.fn(), wizardConfirm: vi.fn(), dmarcData: vi.fn(),
    dmarcRecordDiff: vi.fn(), dmarcMarkPublished: vi.fn(), tlsData: vi.fn(),
    tlsRecordDiff: vi.fn(), tlsMarkPublished: vi.fn(), tlsDomainSummary: vi.fn(),
    certs: vi.fn(), probeCerts: vi.fn(), dnsTimeline: vi.fn(),
    dnsTimelineCount: vi.fn(), dnsTenantTimeline: vi.fn(), dnsTenantCount: vi.fn(),
    alerts: vi.fn(), markAlertRead: vi.fn(), advisor: vi.fn(),
  },
  setToken: vi.fn(),
  clearToken: vi.fn(),
  getToken: vi.fn(() => null),
}))

// Typed handles on the injected mocks
const mockLogin    = vi.mocked(client.api.login)
const mockSetToken = vi.mocked(client.setToken)
const mockClear    = vi.mocked(client.clearToken)

beforeEach(() => {
  vi.clearAllMocks()
})

describe('auth store', () => {

  describe('login()', () => {
    it('populates workspaceName from response', async () => {
      mockLogin.mockResolvedValueOnce({
        access_token: 'tok123', user_id: 'u1', tenant_id: 't1',
        full_name: 'Alice', role: 'admin', workspace_name: 'Acme Corp',
      })
      const auth = useAuthStore()
      await auth.login('alice@acme.com', 'secret')
      expect(auth.workspaceName).toBe('Acme Corp')
    })

    it('sets isAuthenticated to true on success', async () => {
      mockLogin.mockResolvedValueOnce({
        access_token: 'tok', user_id: 'u', tenant_id: 't',
        full_name: '', role: 'admin', workspace_name: 'WS',
      })
      const auth = useAuthStore()
      expect(auth.isAuthenticated).toBe(false)
      await auth.login('x@x.com', 'p')
      expect(auth.isAuthenticated).toBe(true)
    })

    it('calls setToken with the returned access_token', async () => {
      mockLogin.mockResolvedValueOnce({
        access_token: 'mytoken', user_id: 'u', tenant_id: 't',
        full_name: '', role: 'admin', workspace_name: '',
      })
      const auth = useAuthStore()
      await auth.login('x@x.com', 'p')
      expect(mockSetToken).toHaveBeenCalledWith('mytoken')
    })

    it('stores all fields from response', async () => {
      mockLogin.mockResolvedValueOnce({
        access_token: 'tok', user_id: 'uid', tenant_id: 'tid',
        full_name: 'Bob Smith', role: 'viewer', workspace_name: 'Bob Co',
      })
      const auth = useAuthStore()
      await auth.login('bob@bob.com', 'pass')
      expect(auth.userId).toBe('uid')
      expect(auth.tenantId).toBe('tid')
      expect(auth.fullName).toBe('Bob Smith')
      expect(auth.role).toBe('viewer')
    })
  })

  describe('logout()', () => {
    it('clears workspaceName', async () => {
      mockLogin.mockResolvedValueOnce({
        access_token: 'tok', user_id: 'u', tenant_id: 't',
        full_name: 'Alice', role: 'admin', workspace_name: 'Acme',
      })
      const auth = useAuthStore()
      await auth.login('a@a.com', 'p')
      auth.logout()
      expect(auth.workspaceName).toBe('')
    })

    it('sets isAuthenticated to false', async () => {
      mockLogin.mockResolvedValueOnce({
        access_token: 't', user_id: 'u', tenant_id: 't',
        full_name: '', role: 'admin', workspace_name: '',
      })
      const auth = useAuthStore()
      await auth.login('x@x.com', 'p')
      auth.logout()
      expect(auth.isAuthenticated).toBe(false)
    })

    it('calls clearToken', () => {
      const auth = useAuthStore()
      auth.logout()
      expect(mockClear).toHaveBeenCalled()
    })

    it('clears token ref', async () => {
      mockLogin.mockResolvedValueOnce({
        access_token: 'tok', user_id: 'u', tenant_id: 't',
        full_name: '', role: 'admin', workspace_name: '',
      })
      const auth = useAuthStore()
      await auth.login('x@x.com', 'p')
      auth.logout()
      expect(auth.token).toBeNull()
    })
  })
})
