// ABOUTME: Tests for the authenticated sidebar navigation components.
// ABOUTME: Covers AppSidebar nav links, OrgSwitcher org display, and UserMenu user display.

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { useAuthStore } from '@/stores/auth'

// Mock vue-router
vi.mock('vue-router', () => ({
  useRoute: vi.fn(() => ({ path: '/cves' })),
  useRouter: vi.fn(() => ({ push: vi.fn() })),
  RouterLink: {
    name: 'RouterLink',
    props: ['to'],
    template: '<a :href="to"><slot /></a>',
  },
}))

// Mock API client (needed by auth store)
vi.mock('@/lib/api/client', () => ({
  default: {
    GET: vi.fn(),
    POST: vi.fn(),
  },
}))

function seedAuthStore() {
  const auth = useAuthStore()
  auth.user = {
    user_id: 'u1',
    email: 'sam@example.com',
    display_name: 'Sam Carter',
    orgs: [
      { org_id: 'org-1', name: 'Acme Corp', role: 'owner' },
      { org_id: 'org-2', name: 'Globex Inc', role: 'member' },
    ],
  }
  auth.setActiveOrg('org-1')
  return auth
}

describe('AppSidebar', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
  })

  describe('navigation links', () => {
    it('renders all main navigation links', async () => {
      seedAuthStore()
      const { default: AppSidebar } = await import('@/components/AppSidebar.vue')
      const wrapper = mount(AppSidebar)

      const text = wrapper.text()
      expect(text).toContain('CVE Search')
      expect(text).toContain('Watchlists')
    })

    it('renders settings navigation links', async () => {
      seedAuthStore()
      const { default: AppSidebar } = await import('@/components/AppSidebar.vue')
      const wrapper = mount(AppSidebar)

      const text = wrapper.text()
      expect(text).toContain('Members')
      expect(text).toContain('Groups')
    })

    it('renders admin navigation links', async () => {
      seedAuthStore()
      const { default: AppSidebar } = await import('@/components/AppSidebar.vue')
      const wrapper = mount(AppSidebar)

      const text = wrapper.text()
      expect(text).toContain('Feed Status')
    })

    it('links point to correct routes', async () => {
      seedAuthStore()
      const { default: AppSidebar } = await import('@/components/AppSidebar.vue')
      const wrapper = mount(AppSidebar)

      const links = wrapper.findAll('a')
      const hrefs = links.map((l) => l.attributes('href'))
      expect(hrefs).toContain('/cves')
      expect(hrefs).toContain('/watchlists')
      expect(hrefs).toContain('/settings/members')
      expect(hrefs).toContain('/settings/groups')
      expect(hrefs).toContain('/admin/feeds')
    })
  })
})

describe('OrgSwitcher', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
  })

  it('shows active org name', async () => {
    seedAuthStore()
    const { default: OrgSwitcher } = await import('@/components/OrgSwitcher.vue')
    const wrapper = mount(OrgSwitcher)

    expect(wrapper.text()).toContain('Acme Corp')
  })

  it('shows placeholder when no active org', async () => {
    const auth = useAuthStore()
    auth.user = {
      user_id: 'u1',
      email: 'sam@example.com',
      display_name: 'Sam Carter',
      orgs: [
        { org_id: 'org-1', name: 'Acme Corp', role: 'owner' },
        { org_id: 'org-2', name: 'Globex Inc', role: 'member' },
      ],
    }
    // No active org set

    const { default: OrgSwitcher } = await import('@/components/OrgSwitcher.vue')
    const wrapper = mount(OrgSwitcher)

    expect(wrapper.text()).toContain('Select org')
  })
})

describe('UserMenu', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    localStorage.clear()
  })

  it('shows user display name', async () => {
    seedAuthStore()
    const { default: UserMenu } = await import('@/components/UserMenu.vue')
    const wrapper = mount(UserMenu)

    expect(wrapper.text()).toContain('Sam Carter')
  })

  it('shows user email', async () => {
    seedAuthStore()
    const { default: UserMenu } = await import('@/components/UserMenu.vue')
    const wrapper = mount(UserMenu)

    expect(wrapper.text()).toContain('sam@example.com')
  })
})
