import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { SandboxTab } from './SandboxTab'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import * as api from '@/api/config'
import { ApiError } from '@/api/client'
import { vi, describe, it, expect, beforeEach } from 'vitest'

vi.mock('@/api/config', () => ({
  fetchSandbox: vi.fn(),
  saveSandbox: vi.fn(),
  fetchSandboxTemplates: vi.fn(),
  saveSandboxTemplates: vi.fn(),
}))

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
)

beforeEach(() => {
  queryClient.clear()
  vi.mocked(api.fetchSandbox).mockResolvedValue({ content: '', path: '/etc/sudo-logger/sandbox.yaml' })
  vi.mocked(api.fetchSandboxTemplates).mockResolvedValue({})
})

describe('SandboxTab', () => {
  it('renders the feature list and enabled state from the loaded config', async () => {
    render(<SandboxTab />, { wrapper })

    expect(await screen.findByText('Process Sandbox')).toBeInTheDocument()
    expect(screen.getByText('/etc/sudo-logger/sandbox.yaml')).toBeInTheDocument()
    expect(screen.getByText('Block AF_NETLINK')).toBeInTheDocument()
    expect(screen.getByRole('switch')).toHaveAttribute('data-state', 'checked')
    expect(screen.getByRole('button', { name: 'Save sandbox.yaml' })).toBeDisabled()
  })

  it('shows a diff confirmation and saves after toggling a feature', async () => {
    vi.mocked(api.saveSandbox).mockResolvedValue(undefined)
    render(<SandboxTab />, { wrapper })
    await screen.findByText('Process Sandbox')

    fireEvent.click(screen.getByText('Block AF_NETLINK'))

    const saveBtn = screen.getByRole('button', { name: 'Save sandbox.yaml' })
    expect(saveBtn).not.toBeDisabled()
    fireEvent.click(saveBtn)

    expect(await screen.findByText('Confirm sandbox change')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Push change' }))

    await waitFor(() => expect(api.saveSandbox).toHaveBeenCalled())
    expect(vi.mocked(api.saveSandbox).mock.calls[0][0]).toContain('deny_netlink: false')
  })

  it('opens the step-up dialog when the save requires re-authentication', async () => {
    vi.mocked(api.saveSandbox).mockRejectedValue(
      new ApiError(403, JSON.stringify({ error: 'stepup_required', auth_source: 'local' }))
    )
    render(<SandboxTab />, { wrapper })
    await screen.findByText('Process Sandbox')

    fireEvent.click(screen.getByRole('switch'))
    fireEvent.click(screen.getByRole('button', { name: 'Save sandbox.yaml' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Push change' }))

    expect(await screen.findByText("Confirm it's you")).toBeInTheDocument()
  })
})
