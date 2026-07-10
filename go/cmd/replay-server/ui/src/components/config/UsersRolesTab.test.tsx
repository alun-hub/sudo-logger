import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { UsersRolesTab } from './UsersRolesTab'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import * as api from '@/api/config'
import { vi, describe, it, expect, beforeEach } from 'vitest'

vi.mock('@/api/config', () => ({
  fetchUsers: vi.fn(),
  upsertUser: vi.fn(),
  deleteUser: vi.fn(),
  fetchRoles: vi.fn(),
  createRole: vi.fn(),
  updateRole: vi.fn(),
  deleteRole: vi.fn(),
}))

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
)

beforeEach(() => {
  queryClient.clear()
  vi.mocked(api.fetchUsers).mockResolvedValue([
    { username: 'alice', role: 'admin', source: 'local' },
  ])
  vi.mocked(api.fetchRoles).mockResolvedValue([
    { name: 'admin', permissions: ['config:write'] },
    { name: 'viewer', permissions: [] },
  ])
})

describe('UsersRolesTab', () => {
  it('renders the users and roles tables', async () => {
    render(<UsersRolesTab />, { wrapper })

    expect(await screen.findByText('alice')).toBeInTheDocument()
    expect(screen.getAllByText('admin')).toHaveLength(2) // alice's role badge + the admin role row
    expect(screen.getByText('viewer')).toBeInTheDocument()
    expect(screen.getByText('config: write')).toBeInTheDocument()
  })

  it('creates a new local user via the Add User modal', async () => {
    vi.mocked(api.upsertUser).mockResolvedValue(undefined)
    render(<UsersRolesTab />, { wrapper })
    await screen.findByText('alice')

    fireEvent.click(screen.getByRole('button', { name: /Add User/i }))
    fireEvent.change(await screen.findByPlaceholderText('alice'), { target: { value: 'bob' } })
    fireEvent.click(screen.getByRole('button', { name: 'Save User' }))

    await waitFor(() => expect(api.upsertUser).toHaveBeenCalled())
    const [saved] = vi.mocked(api.upsertUser).mock.calls[0]
    expect(saved).toMatchObject({ username: 'bob', role: 'viewer', source: 'local' })
  })

  it('deletes a user after confirming', async () => {
    vi.mocked(api.deleteUser).mockResolvedValue(undefined)
    render(<UsersRolesTab />, { wrapper })
    await screen.findByText('alice')

    const row = screen.getByText('alice').closest('tr')!
    fireEvent.click(row.querySelectorAll('button')[1])

    expect(await screen.findByText('Delete User')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))

    await waitFor(() => expect(api.deleteUser).toHaveBeenCalled())
    expect(vi.mocked(api.deleteUser).mock.calls[0][0]).toBe('alice')
  })
})
