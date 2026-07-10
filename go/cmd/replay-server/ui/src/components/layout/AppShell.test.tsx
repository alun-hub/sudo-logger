import { render, screen, fireEvent } from '@testing-library/react'
import { AppShell } from './AppShell'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import * as configApi from '@/api/config'
import * as approvalsApi from '@/api/approvals'
import { ApiError } from '@/api/client'
import { vi, describe, it, expect, beforeEach } from 'vitest'

vi.mock('@/api/config', () => ({
  fetchMe: vi.fn(),
}))
vi.mock('@/api/approvals', () => ({
  fetchApprovals: vi.fn(),
}))

const navigateSpy = vi.fn()
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => navigateSpy }
})

function renderShell() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={['/']}>
        <AppShell>
          <div>page content</div>
        </AppShell>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

beforeEach(() => {
  navigateSpy.mockClear()
  vi.mocked(approvalsApi.fetchApprovals).mockResolvedValue([])
})

describe('AppShell', () => {
  it('shows all tabs and user info for an admin', async () => {
    vi.mocked(configApi.fetchMe).mockResolvedValue({ user: 'alice', role: 'admin', permissions: [] })
    renderShell()

    expect(await screen.findByText('alice')).toBeInTheDocument()
    expect(screen.getByText('admin')).toBeInTheDocument()
    expect(screen.getByText('Sessions')).toBeInTheDocument()
    expect(screen.getByText('Reports')).toBeInTheDocument()
    expect(screen.getByText('Policy')).toBeInTheDocument()
    expect(screen.getByText('Config')).toBeInTheDocument()
    expect(screen.getByText('Approvals')).toBeInTheDocument()
    expect(screen.getByText('page content')).toBeInTheDocument()
  })

  it('hides permission-gated tabs for a viewer with no extra permissions', async () => {
    vi.mocked(configApi.fetchMe).mockResolvedValue({ user: 'bob', role: 'viewer', permissions: [] })
    renderShell()

    expect(await screen.findByText('bob')).toBeInTheDocument()
    expect(screen.getByText('Sessions')).toBeInTheDocument()
    expect(screen.queryByText('Reports')).not.toBeInTheDocument()
    expect(screen.queryByText('Policy')).not.toBeInTheDocument()
    expect(screen.queryByText('Config')).not.toBeInTheDocument()
    expect(screen.queryByText('Approvals')).not.toBeInTheDocument()
  })

  it('redirects to /login when fetchMe returns 401', async () => {
    vi.mocked(configApi.fetchMe).mockRejectedValue(new ApiError(401, 'unauthorized'))
    renderShell()

    await vi.waitFor(() => expect(navigateSpy).toHaveBeenCalledWith('/login'))
  })

  it('shows a pending-approvals badge on the Approvals tab', async () => {
    vi.mocked(configApi.fetchMe).mockResolvedValue({ user: 'alice', role: 'admin', permissions: [] })
    vi.mocked(approvalsApi.fetchApprovals).mockResolvedValue([
      { id: '1', status: 'pending' } as never,
      { id: '2', status: 'approved' } as never,
    ])
    renderShell()

    expect(await screen.findByText('1')).toBeInTheDocument()
  })

  it('opens the help dialog on "?"', async () => {
    vi.mocked(configApi.fetchMe).mockResolvedValue({ user: 'alice', role: 'admin', permissions: [] })
    renderShell()
    await screen.findByText('alice')

    fireEvent.keyDown(document, { key: '?' })
    expect(await screen.findByText('Help & Reference')).toBeInTheDocument()
  })
})
