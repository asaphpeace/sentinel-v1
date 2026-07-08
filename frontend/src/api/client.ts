const BASE = '/api'

let _token: string | null = localStorage.getItem('sentinel_token')

export function setToken(t: string) {
  _token = t
  localStorage.setItem('sentinel_token', t)
}
export function clearToken() {
  _token = null
  localStorage.removeItem('sentinel_token')
}
export function getToken() { return _token }

// Emitted when the backend returns 403 upgrade_required — components listen
// for this to show an upgrade prompt without coupling to the API layer.
export const upgradeRequired = {
  _handlers: [] as Array<(detail: { code: string; message: string; current_plan: string }) => void>,
  on(fn: (detail: any) => void) { this._handlers.push(fn) },
  off(fn: (detail: any) => void) { this._handlers = this._handlers.filter(h => h !== fn) },
  emit(detail: any) { this._handlers.forEach(h => h(detail)) },
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (_token) headers['Authorization'] = `Bearer ${_token}`
  const res = await fetch(`${BASE}${path}`, { ...init, headers: { ...headers, ...(init.headers as Record<string,string> || {}) } })
  if (res.status === 401) { clearToken(); window.location.href = '/login'; throw new Error('Unauthorized') }
  if (!res.ok) {
    const e = await res.json().catch(() => ({}))
    const detail = e.detail
    // Surface upgrade prompts globally so any component that hits a limit
    // gets a consistent upgrade CTA without each one handling 403 manually.
    if (res.status === 403 && detail && typeof detail === 'object' && detail.upgrade_required) {
      upgradeRequired.emit(detail)
    }
    throw new Error(typeof detail === 'string' ? detail : detail?.message || res.statusText)
  }
  if (res.status === 204 || res.headers.get('content-length') === '0') return undefined as T
  return res.json()
}

export const api = {
  // Auth
  login: (email: string, password: string) =>
    request<any>('/auth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username: email, password }),
    }),

  register: (email: string, password: string, fullName?: string, workspaceName?: string, termsAccepted = false) =>
    request<any>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, full_name: fullName, workspace_name: workspaceName, terms_accepted: termsAccepted }),
    }),

  // Overview
  overview: () => request<any>('/overview'),
  threatSurface: (days = 30) => request<any>(`/overview/threat-surface?days=${days}`),
  readinessRollup: () => request<any>('/overview/readiness-rollup'),
  allCerts: () => request<any[]>('/overview/certs'),
  reportData: (periodDays = 30) => request<any>(`/overview/report-data?period_days=${periodDays}`),

  // Domains
  domains: () => request<any[]>('/domains'),
  domain: (id: string) => request<any>(`/domains/${id}`),
  deleteDomain: (id: string) => request<any>(`/domains/${id}`, { method: 'DELETE' }),
  syncDomainDns: (id: string) => request<any>(`/domains/${id}/sync-dns`, { method: 'POST' }),
  domainRecommendations: (id: string) => request<any[]>(`/domains/${id}/recommendations`),
  simulateDmarcPolicy: (id: string) => request<any>(`/domains/${id}/simulate-policy`),
  discoverSubdomains: (id: string) => request<any[]>(`/domains/${id}/discover-subdomains`),
  setSubdomainDisposition: (id: string, hostname: string, disposition: string, reason?: string) =>
    request<any>(`/domains/${id}/subdomain-dispositions`, {
      method: 'POST',
      body: JSON.stringify({ hostname, disposition, reason: reason ?? null }),
    }),
  registrarInstructions: (id: string) => request<any>(`/domains/${id}/registrar-instructions`),
  checkDnsLive: (id: string, recordType: string) => request<{ exists: boolean }>(`/domains/${id}/check-dns-live?record_type=${recordType}`),
  emailInstructions: (id: string, toEmail: string, recordType: string) =>
    request<{ sent: boolean }>(`/domains/${id}/email-instructions`, {
      method: 'POST',
      body: JSON.stringify({ to_email: toEmail, record_type: recordType }),
    }),
  // Audit log (Enterprise only)
  auditLog: (limit = 50, offset = 0) => request<any[]>(`/audit-log?limit=${limit}&offset=${offset}`),
  auditLogCount: () => request<{ count: number }>('/audit-log/count'),

  // Wizard — one domain per call, backend expects { names: [...] } and returns array
  wizardStart:   (domain: string) => request<any[]>('/domains/wizard/start',    { method: 'POST', body: JSON.stringify({ names: [domain] }) }).then(r => r[0]),
  wizardTlsInfo: (domain: string) => request<any[]>('/domains/wizard/tls-info', { method: 'POST', body: JSON.stringify({ names: [domain] }) }).then(r => r[0]),
  wizardConfirm: (domain: string) => request<any>('/domains/wizard/confirm',    { method: 'POST', body: JSON.stringify({ names: [domain] }) }),
  wizardAbort:   (names: string[]) => request<void>('/domains/wizard/abort',    { method: 'POST', body: JSON.stringify({ names }) }),
  wizardDetectPlatforms: (domain: string) => request<{ detected: string[]; mimecast_detected: boolean }>('/domains/wizard/detect-platforms', { method: 'POST', body: JSON.stringify({ domain }) }),

  // DMARC
  dmarcData:          (domainId: string) => request<any>(`/domains/${domainId}/dmarc`),
  dmarcRecordDiff:    (domainId: string) => request<any>(`/domains/${domainId}/dmarc/record-diff`),
  dmarcMarkPublished: (domainId: string) => request<any>(`/domains/${domainId}/dmarc/mark-published`, { method: 'POST' }),

  // TLS
  tlsData:          (domainId: string) => request<any>(`/domains/${domainId}/tls`),
  tlsRecordDiff:    (domainId: string) => request<any>(`/domains/${domainId}/tls/record-diff`),
  tlsMarkPublished: (domainId: string) => request<any>(`/domains/${domainId}/tls/mark-published`, { method: 'POST' }),
  tlsDomainSummary: () => request<any[]>('/overview/tls-summary'),
  setMtaStsHostingMode: (domainId: string, mode: 'self' | 'managed') =>
    request<any>(`/domains/${domainId}/mta-sts/hosting-mode`, { method: 'POST', body: JSON.stringify({ mode }) }),
  mtaStsHostingStatus: (domainId: string) => request<any>(`/domains/${domainId}/mta-sts/hosting-status`),

  // Certs
  certs:      (domainId: string) => request<any[]>(`/domains/${domainId}/certs`),
  probeCerts: (domainId: string) => request<any>(`/domains/${domainId}/certs/probe`, { method: 'POST' }),

  // DNS
  dnsTimeline:       (domainId: string, limit = 50, offset = 0) => request<any[]>(`/domains/${domainId}/dns-timeline?limit=${limit}&offset=${offset}`),
  dnsTimelineCount:  (domainId: string) => request<any>(`/domains/${domainId}/dns-timeline/count`),
  dnsTenantTimeline: (limit = 100, offset = 0) => request<any[]>(`/tenant/dns-timeline?limit=${limit}&offset=${offset}`),
  dnsTenantCount:    () => request<any>('/tenant/dns-timeline/count'),

  // Concept Cards
  conceptRender: (id: string, context: Record<string, any> = {}) =>
    request<any>(`/concepts/${id}/render`, { method: 'POST', body: JSON.stringify({ context }) }),
  conceptMarkSeen: (id: string) => request<any>(`/concepts/${id}/seen`, { method: 'POST' }),
  conceptsAll: () => request<any[]>('/concepts'),

  // Alerts
  alerts: () => request<any[]>('/alerts'),
  markAlertRead: (id: string) => request<any>(`/alerts/${id}/read`, { method: 'POST' }),

  // Sending platforms
  platformCatalog: () => request<any[]>(`/platforms/catalog`),
  platformStatus: (domainId: string) => request<any[]>(`/domains/${domainId}/platforms/status`),
  declarePlatform: (domainId: string, platformKey: string, customName?: string) => {
    const q = customName ? `?custom_name=${encodeURIComponent(customName)}` : ''
    return request<any>(`/domains/${domainId}/platforms/${platformKey}/declare${q}`, { method: 'POST' })
  },
  removePlatform: (domainId: string, platformKey: string) =>
    request<any>(`/domains/${domainId}/platforms/${platformKey}`, { method: 'DELETE' }),
  platformSetupCard: (domainId: string, platformKey: string) =>
    request<any>(`/domains/${domainId}/platforms/${platformKey}/setup`),
  emailPlatformInstructions: (domainId: string, platformKey: string, toEmail: string) =>
    request<{ ok: boolean }>(`/domains/${domainId}/platforms/${platformKey}/email-instructions`, {
      method: 'POST',
      body: JSON.stringify({ to_email: toEmail }),
    }),

  // Public scan
  scanDomain: (domain: string) =>
    request<any>('/scan', { method: 'POST', body: JSON.stringify({ domain }) }),

  // Advisor
  // force=true bypasses the unchanged-data guard — pass it only from an
  // explicit "Regenerate" click, never from the passive auto-refresh that
  // fires after a cached page load (that one should skip the API call
  // when nothing changed, to preserve Claude usage).
  advisor: (screen: string, domainId?: string, cachedOnly?: boolean, force?: boolean) => {
    const q = new URLSearchParams({ screen })
    if (domainId) q.set('domain_id', domainId)
    if (cachedOnly) q.set('cached_only', 'true')
    if (force) q.set('force', 'true')
    return request<any>(`/advisor?${q}`)
  },
  advisorChat: (message: string, history: { role: string; content: string }[], screen: string, domainId?: string) =>
    request<{ reply: string; model: string; citations: string[] }>('/advisor/chat', {
      method: 'POST',
      body: JSON.stringify({ message, history, screen, domain_id: domainId ?? null }),
    }),
  advisorCertSummary: (domainId?: string, cachedOnly?: boolean, force?: boolean) => {
    const q = new URLSearchParams()
    if (domainId) q.set('domain_id', domainId)
    if (cachedOnly) q.set('cached_only', 'true')
    if (force) q.set('force', 'true')
    const qs = q.toString()
    return request<any>(`/advisor/cert-summary${qs ? '?' + qs : ''}`)
  },
  advisorDnsSummary: (domainId?: string, cachedOnly?: boolean, force?: boolean) => {
    const q = new URLSearchParams()
    if (domainId) q.set('domain_id', domainId)
    if (cachedOnly) q.set('cached_only', 'true')
    if (force) q.set('force', 'true')
    const qs = q.toString()
    return request<any>(`/advisor/dns-summary${qs ? '?' + qs : ''}`)
  },
  regenerateNarrative: () => request<any>('/overview/narrative/regenerate', { method: 'POST' }),

  // Billing
  billingPlans:    () => request<any[]>('/billing/plans'),
  billingStatus:   () => request<any>('/billing/status'),
  updateReportSchedule: (schedule: 'off' | 'weekly' | 'monthly') =>
    request<any>('/billing/report-schedule', { method: 'PATCH', body: JSON.stringify({ schedule }) }),
  changePlan:      (plan: string) => request<any>('/billing/plan', { method: 'POST', body: JSON.stringify({ plan }) }),
  billingCheckout: (plan: string, billing_cycle: string) => request<{ checkout_url: string; session_id: string }>('/billing/checkout', { method: 'POST', body: JSON.stringify({ plan, billing_cycle }) }),
  billingPortal:   () => request<{ portal_url: string }>('/billing/portal', { method: 'POST' }),

  // Team / invites
  team:          () => request<any[]>('/auth/team'),
  invites:       () => request<any[]>('/auth/invites'),
  createInvite:  (email: string, role: string) => request<any>('/auth/invite', { method: 'POST', body: JSON.stringify({ email, role }) }),
  revokeInvite:  (id: string) => request<any>(`/auth/invite/${id}`, { method: 'DELETE' }),
  getInvite:     (token: string) => request<any>(`/auth/invite/${token}`),
  acceptInvite:  (token: string, full_name: string, password: string, terms_accepted: boolean) =>
    request<any>('/auth/accept-invite', { method: 'POST', body: JSON.stringify({ token, full_name, password, terms_accepted }) }),
  updateMember:  (id: string, patch: any) => request<any>(`/auth/team/${id}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  removeMember:  (id: string) => request<any>(`/auth/team/${id}`, { method: 'DELETE' }),
  verifyOwnership: (domainId: string) => request<any>(`/domains/${domainId}/verify-ownership`, { method: 'POST' }),

  twoFaChallenge: (pre_auth_token: string, code: string) =>
    request<any>('/auth/2fa/challenge', { method: 'POST', body: JSON.stringify({ pre_auth_token, code }) }),

  // Profile / account
  me:             () => request<any>('/auth/me'),
  updateMe:       (patch: any) => request<any>('/auth/me', { method: 'PATCH', body: JSON.stringify(patch) }),
  changePassword: (current_password: string, new_password: string) =>
    request<void>('/auth/change-password', { method: 'POST', body: JSON.stringify({ current_password, new_password }) }),
  forgotPassword: (email: string) =>
    request<{ message: string }>('/auth/forgot-password', { method: 'POST', body: JSON.stringify({ email }) }),
  resetPassword: (token: string, new_password: string) =>
    request<void>('/auth/reset-password', { method: 'POST', body: JSON.stringify({ token, new_password }) }),
  verifyEmail: (token: string) =>
    request<void>('/auth/verify-email', { method: 'POST', body: JSON.stringify({ token }) }),
  resendVerification: () =>
    request<void>('/auth/resend-verification', { method: 'POST' }),
  deleteAccount:  () => request<void>('/auth/account', { method: 'DELETE' }),
  enable2fa:      () => request<any>('/auth/2fa/enable', { method: 'POST' }),
  verify2fa:      (code: string) => request<void>('/auth/2fa/verify', { method: 'POST', body: JSON.stringify({ code }) }),
  disable2fa:     (code: string) => request<void>('/auth/2fa/disable', { method: 'POST', body: JSON.stringify({ code }) }),

  // MSP
  mspClients:      () => request<any[]>('/msp/clients'),
  mspCreateClient: (payload: any) => request<any>('/msp/clients', { method: 'POST', body: JSON.stringify(payload) }),
  mspGetClient:    (id: string) => request<any>(`/msp/clients/${id}`),
  mspUpdateClient: (id: string, patch: any) => request<any>(`/msp/clients/${id}`, { method: 'PATCH', body: JSON.stringify(patch) }),
  mspDeleteClient: (id: string) => request<void>(`/msp/clients/${id}`, { method: 'DELETE' }),
  mspInviteToClient: (clientId: string, payload: any) => request<any>(`/msp/clients/${clientId}/invite`, { method: 'POST', body: JSON.stringify(payload) }),

  // Generic escape hatches for one-off requests
  get:  <T = any>(path: string) => request<T>(path),
  post: <T = any>(path: string, body: any) => request<T>(path, { method: 'POST', body: JSON.stringify(body) }),
}
