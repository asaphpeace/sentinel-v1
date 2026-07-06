/**
 * Shared API mock for frontend unit tests.
 *
 * IMPORTANT — Vitest hoists vi.mock() before all imports, so the mock factory
 * must be self-contained. Copy this boilerplate verbatim at the top of any
 * test file that touches the API:
 *
 *   import * as client from '@/api/client'
 *
 *   vi.mock('@/api/client', () => ({
 *     api: {
 *       login: vi.fn(), register: vi.fn(), overview: vi.fn(), ...
 *     },
 *     setToken: vi.fn(),
 *     clearToken: vi.fn(),
 *     getToken: vi.fn(() => null),
 *   }))
 *
 *   // Then get typed handles via vi.mocked():
 *   const mockLogin = vi.mocked(client.api.login)
 *
 * This file exports resetApiMocks() — call it in beforeEach to clear call
 * history between tests without re-declaring the mock.
 */
import { vi } from 'vitest'

export const mockApi = {
  // Auth
  login: vi.fn(),
  register: vi.fn(),

  // Overview
  overview: vi.fn(),
  threatSurface: vi.fn(),
  allCerts: vi.fn(),
  reportData: vi.fn(),

  // Domains
  domains: vi.fn(),
  domain: vi.fn(),
  deleteDomain: vi.fn(),
  syncDomainDns: vi.fn(),
  wizardStart: vi.fn(),
  wizardTlsInfo: vi.fn(),
  wizardConfirm: vi.fn(),

  // DMARC
  dmarcData: vi.fn(),
  dmarcRecordDiff: vi.fn(),
  dmarcMarkPublished: vi.fn(),

  // TLS
  tlsData: vi.fn(),
  tlsRecordDiff: vi.fn(),
  tlsMarkPublished: vi.fn(),
  tlsDomainSummary: vi.fn(),

  // Certs
  certs: vi.fn(),
  probeCerts: vi.fn(),

  // DNS
  dnsTimeline: vi.fn(),
  dnsTimelineCount: vi.fn(),
  dnsTenantTimeline: vi.fn(),
  dnsTenantCount: vi.fn(),

  // Misc
  alerts: vi.fn(),
  markAlertRead: vi.fn(),
  advisor: vi.fn(),
}

export const mockSetToken = vi.fn()
export const mockClearToken = vi.fn()
export const mockGetToken = vi.fn(() => null as string | null)

/** Returns the full mock module — pass this to vi.mock's factory return. */
export function buildApiMock() {
  return {
    api: mockApi,
    setToken: mockSetToken,
    clearToken: mockClearToken,
    getToken: mockGetToken,
  }
}

/** Reset all mocks between tests. Call in beforeEach if needed. */
export function resetApiMocks() {
  Object.values(mockApi).forEach(fn => fn.mockReset())
  mockSetToken.mockReset()
  mockClearToken.mockReset()
  mockGetToken.mockReset().mockReturnValue(null)
}
