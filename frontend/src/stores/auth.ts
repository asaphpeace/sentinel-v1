import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, setToken, clearToken, getToken } from '@/api/client'

const SESSION_KEY = 'sentinel_session'

function loadSession() {
  try { return JSON.parse(localStorage.getItem(SESSION_KEY) || 'null') } catch { return null }
}
function saveSession(data: Record<string, string>) {
  localStorage.setItem(SESSION_KEY, JSON.stringify(data))
}
function clearSession() {
  localStorage.removeItem(SESSION_KEY)
}

const _saved = loadSession()

export const useAuthStore = defineStore('auth', () => {
  const token         = ref<string | null>(getToken())
  const userId        = ref<string | null>(_saved?.userId ?? null)
  const tenantId      = ref<string | null>(_saved?.tenantId ?? null)
  const fullName      = ref<string>(_saved?.fullName ?? '')
  const role          = ref<string>(_saved?.role ?? '')
  const workspaceName = ref<string>(_saved?.workspaceName ?? '')
  const plan          = ref<string>(_saved?.plan ?? 'free')
  const isAuthenticated = ref(!!getToken())

  function _applyLoginData(data: any) {
    setToken(data.access_token)
    token.value           = data.access_token
    userId.value          = data.user_id
    tenantId.value        = data.tenant_id
    fullName.value        = data.full_name
    role.value            = data.role
    workspaceName.value   = data.workspace_name
    plan.value            = data.plan ?? 'free'
    isAuthenticated.value = true
    saveSession({
      userId:        data.user_id,
      tenantId:      data.tenant_id,
      fullName:      data.full_name,
      role:          data.role,
      workspaceName: data.workspace_name,
      plan:          data.plan ?? 'free',
    })
  }

  async function login(email: string, password: string) {
    const res = await api.login(email, password)
    if (res.requires_2fa) return res
    _applyLoginData(res)
  }

  function applyLoginData(data: any) {
    _applyLoginData(data)
  }

  function setPlan(p: string) {
    plan.value = p
    const s = loadSession()
    if (s) saveSession({ ...s, plan: p })
  }

  function logout() {
    clearToken()
    clearSession()
    token.value           = null
    userId.value          = null
    tenantId.value        = null
    fullName.value        = ''
    role.value            = ''
    workspaceName.value   = ''
    plan.value            = 'free'
    isAuthenticated.value = false
  }

  const isAdmin = () => role.value === 'admin'

  return { token, userId, tenantId, fullName, role, plan, workspaceName, isAuthenticated, login, applyLoginData, logout, setPlan, isAdmin }
})
