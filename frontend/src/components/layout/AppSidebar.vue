<script setup lang="ts">
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useUiStore } from '@/stores/ui'

const router = useRouter()
const route  = useRoute()
const auth   = useAuthStore()
const ui     = useUiStore()

const nav = [
  { label: 'Portfolio',  group: true },
  { id: 'overview', label: 'Overview',        num: '01', icon: 'grid' },
  { id: 'domains',  label: 'Domains',         num: '02', icon: 'globe' },
  { label: 'Analyze', group: true },
  { id: 'posture',  label: 'Posture',         num: '03', icon: 'pulse' },
  { id: 'dmarc',    label: 'DMARC',           num: '04', icon: 'mail' },
  { id: 'tls',      label: 'MTA-STS & TLS',  num: '05', icon: 'lock' },
  { label: 'Plan',   group: true },
  { id: 'roadmap',  label: 'Roadmap',         num: '06', icon: 'chevron' },
  { id: 'certs',    label: 'Certificates',    num: '07', icon: 'award' },
  { id: 'timeline', label: 'DNS Timeline',    num: '08', icon: 'clock' },
  { label: 'Account', group: true },
  { id: 'billing',  label: 'Plan & Billing',  num: '09', icon: 'billing' },
  { id: 'profile',  label: 'Settings',        num: '10', icon: 'settings' },
  { id: 'msp',      label: 'MSP Clients',     num: '11', icon: 'msp',     mspOnly: true },
  { id: 'audit-log', label: 'Audit Log',      num: '12', icon: 'audit',   enterpriseOnly: true },
  { label: 'Resources', group: true },
  { id: 'docs',     label: 'Documentation',   num: '13', icon: 'book' },
]

const initials = (name: string) => name ? name[0].toUpperCase() : 'A'

function logout() {
  auth.logout()
  router.push({ name: 'login' })
}

function navigate(name: string) {
  router.push({ name })
  ui.closeNav()
}
</script>

<template>
  <aside class="sidebar" :class="{ open: ui.navOpen }">
    <!-- Brand -->
    <div class="brand">
      <div class="logo">
        <svg viewBox="0 0 24 24" fill="none" stroke="#06060f" stroke-width="2.2">
          <path d="M22 6l-10 7L2 6"/><rect x="2" y="4" width="20" height="16" rx="2"/>
        </svg>
      </div>
      <div>
        <div class="brand-name">Sen<b>tinel</b></div>
        <div class="brand-sub">DMARC · MTA-STS</div>
      </div>
    </div>


    <!-- Nav -->
    <template v-for="item in nav" :key="item.label">
      <div v-if="item.group" class="nav-label">{{ item.label }}</div>
      <div v-else-if="!item.mspOnly || ['msp','enterprise'].includes(auth.plan)"
        :class="['nav-item', route.name === item.id ? 'active' : '', item.enterpriseOnly && auth.plan !== 'enterprise' ? 'locked' : '']"
        @click="navigate(item.id!)"
      >
        <!-- icons inline for simplicity -->
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <template v-if="item.icon === 'grid'">
            <rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/>
            <rect x="3" y="14" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/>
          </template>
          <template v-else-if="item.icon === 'globe'">
            <circle cx="12" cy="12" r="10"/>
            <line x1="2" y1="12" x2="22" y2="12"/>
            <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
          </template>
          <path v-else-if="item.icon === 'pulse'" d="M3 12h4l3 8 4-16 3 8h4"/>
          <template v-else-if="item.icon === 'mail'">
            <path d="M22 6l-10 7L2 6"/><rect x="2" y="4" width="20" height="16" rx="2"/>
          </template>
          <template v-else-if="item.icon === 'lock'">
            <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </template>
          <path v-else-if="item.icon === 'chevron'" d="M9 18l6-6-6-6"/>
          <template v-else-if="item.icon === 'award'">
            <circle cx="12" cy="8" r="6"/><path d="M9 13l-2 8 5-3 5 3-2-8"/>
          </template>
          <template v-else-if="item.icon === 'clock'">
            <circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>
          </template>
          <template v-else-if="item.icon === 'billing'">
            <rect x="1" y="4" width="22" height="16" rx="2"/><line x1="1" y1="10" x2="23" y2="10"/>
          </template>
          <template v-else-if="item.icon === 'msp'">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
            <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
            <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
          </template>
          <template v-else-if="item.icon === 'settings'">
            <circle cx="12" cy="12" r="3"/>
            <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>
          </template>
          <template v-else-if="item.icon === 'book'">
            <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/>
            <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>
          </template>
          <template v-else-if="item.icon === 'audit'">
            <path d="M9 11l3 3L22 4"/>
            <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
          </template>
        </svg>
        {{ item.label }}
        <span v-if="item.enterpriseOnly && auth.plan !== 'enterprise'" class="lock-badge" title="Enterprise feature">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
            <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
          </svg>
        </span>
        <span v-else class="num">{{ item.num }}</span>
      </div>
    </template>

    <!-- Add domain CTA -->
    <div class="add-domain-btn" @click="navigate('domains')">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2">
        <path d="M12 5v14M5 12h14"/>
      </svg>
      Add domain
    </div>

    <!-- User footer -->
    <div class="side-user">
      <div class="avatar">{{ initials(auth.fullName) }}</div>
      <div class="user-info">
        <div class="nm">{{ auth.fullName || 'Account' }}</div>
        <div class="rl-row">
          <span class="rl">{{ auth.role || 'Admin' }}</span>
          <span class="plan-pill" @click.stop="router.push({ name: 'billing' })">{{ auth.plan }}</span>
        </div>
        <div class="ws" v-if="auth.workspaceName">{{ auth.workspaceName }}</div>
      </div>
      <button class="logout-btn" title="Sign out" @click.stop="logout">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
          <polyline points="16 17 21 12 16 7"/>
          <line x1="21" y1="12" x2="9" y2="12"/>
        </svg>
      </button>
    </div>
  </aside>
</template>

<style scoped>
.sidebar {
  margin: 14px 0 14px 14px; border-radius: 22px; padding: 18px 14px;
  background: linear-gradient(180deg, rgba(255,255,255,.05), rgba(255,255,255,.012));
  border: 1px solid var(--line); backdrop-filter: blur(14px);
  display: flex; flex-direction: column; gap: 4px;
  position: sticky; top: 14px; height: calc(100vh - 28px); overflow-y: auto;
}
.brand { display: flex; align-items: center; gap: 11px; padding: 4px 8px 14px; }
.logo { width: 36px; height: 36px; border-radius: 11px; flex: none; display: grid; place-items: center; background: radial-gradient(circle at 30% 25%, #2ef5d4, #5b6ef5); box-shadow: 0 0 22px rgba(46,230,197,.45); }
.logo svg { width: 19px; height: 19px; }
.brand-name { font-family: var(--disp); font-weight: 800; font-size: 16px; letter-spacing: -.3px; line-height: 1.1; }
.brand-name b { background: linear-gradient(90deg, #2ee6c5, #5b6ef5); -webkit-background-clip: text; background-clip: text; color: transparent; }
.brand-sub { font-family: var(--mono); font-size: 8.5px; color: var(--teal); letter-spacing: 1.4px; text-transform: uppercase; }
.nav-label { font-family: var(--mono); font-size: 9px; letter-spacing: 1.4px; color: var(--faint); text-transform: uppercase; padding: 12px 12px 5px; }
.nav-item { display: flex; align-items: center; gap: 12px; padding: 9px 13px; border-radius: 12px; color: var(--muted); cursor: pointer; font-weight: 500; font-size: 13px; transition: all .16s ease; }
.nav-item svg { width: 17px; height: 17px; flex: none; opacity: .85; }
.nav-item:hover { background: rgba(255,255,255,.05); color: var(--txt); }
.nav-item.active { background: linear-gradient(90deg, #5b6ef5, #8b5cf6); color: #fff; box-shadow: 0 8px 24px rgba(91,110,245,.45); }
.nav-item.active svg { opacity: 1; }
.num { font-family: var(--mono); font-size: 9.5px; margin-left: auto; opacity: .55; }
.nav-item.locked { opacity: .62; }
.nav-item.locked:hover { opacity: .85; }
.lock-badge { margin-left: auto; display: flex; align-items: center; color: var(--faint); }
.lock-badge svg { width: 12px; height: 12px; opacity: .8; }
.nav-item.active .lock-badge { color: rgba(255,255,255,.8); }
.add-domain-btn {
  display: flex; align-items: center; gap: 8px; margin: 8px 4px 0; padding: 9px 13px;
  border-radius: 12px; border: 1px dashed var(--line2); color: var(--teal);
  cursor: pointer; font-size: 12.5px; font-weight: 600; transition: .15s;
}
.add-domain-btn:hover { background: rgba(46,230,197,.07); border-color: var(--teal); }
.add-domain-btn svg { width: 14px; height: 14px; }
.side-user {
  margin-top: auto; display: flex; align-items: center; gap: 10px;
  padding: 10px 11px; border-radius: 14px;
  background: rgba(255,255,255,.04); border: 1px solid var(--line);
}
.avatar {
  width: 34px; height: 34px; border-radius: 10px; flex: none;
  background: linear-gradient(135deg, #f5417a, #8b5cf6);
  display: grid; place-items: center;
  font-family: var(--disp); font-weight: 700; font-size: 14px; color: #fff;
}
.user-info { flex: 1; min-width: 0; }
.nm { font-size: 12.5px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.rl-row { display: flex; align-items: center; gap: 6px; margin-top: 1px; }
.rl { font-size: 10px; color: var(--muted); text-transform: capitalize; }
.plan-pill { font-family: var(--mono); font-size: 8px; font-weight: 700; letter-spacing: .4px; text-transform: uppercase; background: rgba(91,110,245,.18); color: var(--indigo); padding: 1px 7px; border-radius: 10px; cursor: pointer; transition: background .15s; }
.plan-pill:hover { background: rgba(91,110,245,.3); }
.ws { font-size: 9.5px; color: var(--faint); font-family: var(--mono); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 1px; }
.logout-btn {
  flex: none; background: none; border: none; cursor: pointer;
  color: var(--faint); padding: 5px; border-radius: 8px;
  display: grid; place-items: center; transition: .15s;
}
.logout-btn:hover { background: rgba(255,77,109,.12); color: var(--bad); }
.logout-btn svg { width: 15px; height: 15px; }

@media (max-width: 1000px) {
  .sidebar {
    position: fixed; top: 0; left: 0; bottom: 0; z-index: 100;
    margin: 0; border-radius: 0 22px 22px 0;
    transform: translateX(-100%);
    transition: transform .25s cubic-bezier(.4,0,.2,1);
    height: 100dvh;
  }
  .sidebar.open { transform: translateX(0); }
}
</style>
