// ABOUTME: Vue Router configuration with auth and org guards.
// ABOUTME: Redirects unauthenticated users to login, org-less users to create-org.

import { nextTick } from 'vue'
import {
  createRouter,
  createWebHistory,
  type NavigationGuardWithThis,
  type NavigationHookAfter,
  type RouteRecordRaw,
} from 'vue-router'
import { useAuthStore } from '@/stores/auth'

// Exported for test access.
export const routes: RouteRecordRaw[] = [
  // ── Public routes ──────────────────────────────────────────────
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/LoginView.vue'),
    meta: { layout: 'public', requiresAuth: false, title: 'Log In' },
  },
  {
    path: '/register',
    name: 'register',
    component: () => import('@/views/RegisterView.vue'),
    meta: { layout: 'public', requiresAuth: false, title: 'Register' },
  },
  {
    path: '/invitations/:token',
    name: 'invitation',
    component: () => import('@/views/InvitationView.vue'),
    meta: { layout: 'public', requiresAuth: false, title: 'Invitation' },
  },

  // ── Authenticated routes ───────────────────────────────────────
  {
    path: '/create-org',
    name: 'create-org',
    component: () => import('@/views/CreateOrgView.vue'),
    meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: false, title: 'Create Organization' },
  },
  {
    path: '/cves',
    name: 'cve-search',
    component: () => import('@/views/CveSearchView.vue'),
    meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true, title: 'CVE Search' },
  },
  {
    path: '/cves/:cveId',
    name: 'cve-detail',
    component: () => import('@/views/CveDetailView.vue'),
    meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true, title: 'CVE Detail' },
  },
  {
    path: '/watchlists',
    name: 'watchlists',
    component: () => import('@/views/WatchlistListView.vue'),
    meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true, title: 'Watchlists' },
  },
  {
    path: '/watchlists/:id',
    name: 'watchlist-detail',
    component: () => import('@/views/WatchlistDetailView.vue'),
    meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true, title: 'Watchlist' },
  },
  {
    path: '/settings/members',
    name: 'members',
    component: () => import('@/views/MembersView.vue'),
    meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true, title: 'Members' },
  },
  {
    path: '/settings/groups',
    name: 'groups',
    component: () => import('@/views/GroupsView.vue'),
    meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true, title: 'Groups' },
  },
  {
    path: '/admin/feeds',
    name: 'feed-status',
    component: () => import('@/views/FeedStatusView.vue'),
    meta: { layout: 'authenticated', requiresAuth: true, requiresOrg: true, title: 'Feed Status' },
  },

  // ── Redirects ──────────────────────────────────────────────────
  {
    path: '/',
    redirect: '/cves',
  },

  // ── 404 ────────────────────────────────────────────────────────
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('@/views/NotFoundView.vue'),
    meta: { layout: 'public', requiresAuth: false, title: 'Not Found' },
  },
]

// Exported for test access.
export const authGuard: NavigationGuardWithThis<undefined> = async (to) => {
  const auth = useAuthStore()

  // Try to restore session on first navigation.
  if (!auth.isAuthenticated) {
    await auth.fetchMe()
  }

  const requiresAuth = to.meta.requiresAuth !== false
  const requiresOrg = to.meta.requiresOrg === true

  // Redirect unauthenticated users to login.
  if (requiresAuth && !auth.isAuthenticated) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }

  // Redirect authenticated users away from public-only pages.
  if (
    !requiresAuth &&
    auth.isAuthenticated &&
    (to.name === 'login' || to.name === 'register')
  ) {
    return { name: 'cve-search' }
  }

  // Redirect to create-org if user has no orgs.
  if (requiresOrg && auth.isAuthenticated && auth.user?.orgs?.length === 0) {
    return { name: 'create-org' }
  }

  // Auto-select first org if user has orgs but none selected.
  if (
    requiresOrg &&
    auth.isAuthenticated &&
    !auth.activeOrgId &&
    auth.user?.orgs &&
    auth.user.orgs.length > 0
  ) {
    auth.setActiveOrg(auth.user.orgs[0]!.org_id)
  }
}

// Exported for test access.
export const titleGuard: NavigationHookAfter = (to) => {
  const title = typeof to.meta.title === 'string'
    ? to.meta.title
    : typeof to.name === 'string'
      ? to.name.split('-').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')
      : ''
  document.title = title ? `${title} | CVErt Ops` : 'CVErt Ops'

  // Focus the page heading for screen reader announcement
  nextTick(() => {
    const heading = document.querySelector('h1')
    if (heading instanceof HTMLElement) {
      heading.setAttribute('tabindex', '-1')
      heading.focus()
    }
  })
}

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(authGuard)
router.afterEach(titleGuard)

export default router
