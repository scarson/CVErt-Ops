# UI Walkthrough — 2026-03-06

First visual walkthrough of the frontend after feature/frontend merge.

## Fixed This Session

- [x] **Dark mode**: Added `class="dark"` to `<html>`, `color-scheme: dark` to `.dark` CSS
- [x] **Autofill contrast**: Browser autofill painted light blue on dark inputs — `color-scheme: dark` fixed it
- [x] **Severity badge contrast**: `CveResultsTable.vue` medium badge used `text-black` on yellow — changed to `text-white` on `bg-yellow-600`
- [x] **Logout redirect**: Clicking "Log out" left user on current page — now redirects to `/login`
- [x] **Layout padding**: `AuthenticatedLayout.vue` `<main>` had no padding — added `p-4 md:p-6`; fixes `/cves`, `/settings/members`, `/settings/groups`
- [x] **Create org card width**: Card filled entire content area — added `max-w-md mx-auto`
- [x] **Duplicate watchlist buttons**: Removed empty-state "New Watchlist" button; header button is always visible
- [x] **Ecosystem dropdown overflow**: Replaced native `<select>` with shadcn `Select` (portal-based, scrollable)
- [x] **OAuth buttons**: Added `GET /api/v1/auth/providers` endpoint; login/register pages now hide OAuth buttons + separator when provider is unconfigured

## Open Issues

### Functional
- [ ] `/admin/feeds` — "Coming soon" placeholder; blocked until feed adapters are configured

### UX / Design

- [ ] Package name validation — typos create useless watchlist entries (plan written: `dev/plans/2026-03-06-package-registry-validation-plan.md`)

### Informational (Not Bugs)

- Dual org creation on first user is expected: `BootstrapFirstUserOrg()` creates a personal org for the first user only, plus user can create additional orgs via `/create-org`
- "Email already registered" on re-registration is correct — account persists in the `postgres_data` Docker volume
