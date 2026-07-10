import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { AuthTab } from './AuthTab'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import * as api from '@/api/config'
import { vi, describe, it, expect, beforeEach } from 'vitest'

vi.mock('@/api/config', () => ({
  fetchAuthConfig: vi.fn(),
  saveAuthConfig: vi.fn(),
  fetchRoles: vi.fn(),
  fetchUsers: vi.fn(),
}))

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
)

beforeEach(() => {
  queryClient.clear()
  vi.mocked(api.fetchRoles).mockResolvedValue([
    { name: 'admin', permissions: [] },
    { name: 'viewer', permissions: [] },
  ])
  vi.mocked(api.fetchUsers).mockResolvedValue([
    { username: 'alice', role: 'admin', source: 'local' },
  ])
})

describe('AuthTab', () => {
  it('renders OIDC fields and existing group mappings', async () => {
    vi.mocked(api.fetchAuthConfig).mockResolvedValue({
      source: 'oidc',
      oidc: { issuer: 'https://accounts.example.com', client_id: 'abc', client_secret: '' },
      proxy: { user_header: '', groups_header: '' },
      admin_groups: [],
      group_mappings: [{ group: 'sudoers', role: 'admin' }],
    })
    render(<AuthTab />, { wrapper })

    expect(await screen.findByDisplayValue('https://accounts.example.com')).toBeInTheDocument()
    expect(screen.getByDisplayValue('abc')).toBeInTheDocument()
    expect(screen.getByDisplayValue('sudoers')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Save Auth Settings/i })).toBeDisabled()
  })

  it('enables Save after editing the issuer and submits the updated config', async () => {
    vi.mocked(api.fetchAuthConfig).mockResolvedValue({
      source: 'oidc',
      oidc: { issuer: 'https://old.example.com', client_id: '', client_secret: '' },
      proxy: { user_header: '', groups_header: '' },
      admin_groups: [],
      group_mappings: [],
    })
    vi.mocked(api.saveAuthConfig).mockResolvedValue(undefined)
    render(<AuthTab />, { wrapper })

    const issuer = await screen.findByDisplayValue('https://old.example.com')
    fireEvent.change(issuer, { target: { value: 'https://new.example.com' } })

    const saveBtn = screen.getByRole('button', { name: /Save Auth Settings/i })
    expect(saveBtn).not.toBeDisabled()
    fireEvent.click(saveBtn)

    await waitFor(() => expect(api.saveAuthConfig).toHaveBeenCalled())
    const [savedArg] = vi.mocked(api.saveAuthConfig).mock.calls[0]
    expect(savedArg.oidc.issuer).toBe('https://new.example.com')
  })

  it('adds and removes a group role mapping', async () => {
    vi.mocked(api.fetchAuthConfig).mockResolvedValue({
      source: 'proxy',
      oidc: { issuer: '', client_id: '', client_secret: '' },
      proxy: { user_header: 'X-Forwarded-User', groups_header: 'X-Forwarded-Groups' },
      admin_groups: [],
      group_mappings: [],
    })
    render(<AuthTab />, { wrapper })

    await screen.findByText('No mappings — all authenticated users get the default role.')
    fireEvent.click(screen.getByText('Add mapping'))

    const groupInput = screen.getByPlaceholderText('group-name')
    fireEvent.change(groupInput, { target: { value: 'ops' } })
    expect(groupInput).toHaveValue('ops')

    fireEvent.click(screen.getByRole('button', { name: '' })) // trash icon button
    expect(screen.getByText('No mappings — all authenticated users get the default role.')).toBeInTheDocument()
  })
})
