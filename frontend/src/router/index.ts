import { createRouter, createWebHistory } from 'vue-router'
import { getToken } from '@/api/client'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('@/views/LoginView.vue') },
    { path: '/reset-password', name: 'reset-password', component: () => import('@/views/LoginView.vue') },
    { path: '/verify-email', name: 'verify-email', component: () => import('@/views/VerifyEmailView.vue') },
    { path: '/accept-invite', name: 'accept-invite', component: () => import('@/views/AcceptInviteView.vue') },
    {
      path: '/',
      component: () => import('@/components/layout/AppShell.vue'),
      meta: { requiresAuth: true },
      children: [
        { path: '', name: 'overview',  component: () => import('@/views/OverviewView.vue') },
        { path: 'domains',          name: 'domains',       component: () => import('@/views/DomainsView.vue') },
        { path: 'domains/:id',     name: 'domain-detail', component: () => import('@/views/DomainDetailView.vue') },
        { path: 'posture',    name: 'posture',   component: () => import('@/views/PostureView.vue') },
        { path: 'dmarc',      name: 'dmarc',     component: () => import('@/views/DmarcView.vue') },
        { path: 'tls',        name: 'tls',       component: () => import('@/views/MtaStsView.vue') },
        { path: 'roadmap',    name: 'roadmap',   component: () => import('@/views/RoadmapView.vue') },
        { path: 'certs',      name: 'certs',     component: () => import('@/views/CertificatesView.vue') },
        { path: 'timeline',   name: 'timeline',  component: () => import('@/views/DnsTimelineView.vue') },
        { path: 'profile',    name: 'profile',   component: () => import('@/views/ProfileView.vue') },
        { path: 'billing',    name: 'billing',   component: () => import('@/views/BillingView.vue') },
        { path: 'msp',        name: 'msp',       component: () => import('@/views/MspView.vue') },
        { path: 'audit-log',  name: 'audit-log', component: () => import('@/views/AuditLogView.vue') },
        { path: 'docs',       name: 'docs',      component: () => import('@/views/DocsView.vue') },
      ],
    },
    { path: '/report', name: 'report', component: () => import('@/views/ReportView.vue') },
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach((to) => {
  if (to.meta.requiresAuth && !getToken()) return '/login'
})

export default router
