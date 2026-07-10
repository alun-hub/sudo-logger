import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { SudoersView } from './SudoersView'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import * as api from '@/api/sudoers'
import { ApiError } from '@/api/client'
import { vi, describe, it, expect, beforeEach } from 'vitest'

vi.mock('@/api/sudoers', () => ({
  fetchSudoersHosts: vi.fn(),
  fetchSudoersConfig: vi.fn(),
  saveSudoersConfig: vi.fn(),
  deleteSudoersOverride: vi.fn(),
  fetchSudoersSnapshots: vi.fn(),
}))

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false } },
})

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
)

beforeEach(() => {
  queryClient.clear()
  vi.mocked(api.fetchSudoersHosts).mockResolvedValue([])
  vi.mocked(api.fetchSudoersConfig).mockResolvedValue({
    host: '_default',
    content: 'alice ALL=(ALL) ALL\n',
    is_override: false,
  })
  vi.mocked(api.fetchSudoersSnapshots).mockResolvedValue({ host: '_default', snapshots: [] })
})

describe('SudoersView', () => {
  it('renders the global default editor with the parsed rule', async () => {
    render(<SudoersView />, { wrapper })

    expect(await screen.findByText('Global sudoers Template')).toBeInTheDocument()
    expect(screen.getByText('Global Default')).toBeInTheDocument()
    expect(screen.getByText('alice')).toBeInTheDocument()
  })

  it('shows a diff confirmation and saves the edited rule', async () => {
    vi.mocked(api.saveSudoersConfig).mockResolvedValue({ ok: true })
    render(<SudoersView />, { wrapper })

    await screen.findByText('alice')
    fireEvent.click(screen.getByText('alice'))
    fireEvent.change(screen.getByDisplayValue('alice'), { target: { value: 'bob' } })

    const saveBtn = screen.getByRole('button', { name: /Save Changes/i })
    expect(saveBtn).not.toBeDisabled()
    fireEvent.click(saveBtn)

    expect(await screen.findByText('Confirm sudoers change')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Push change' }))

    await waitFor(() =>
      expect(api.saveSudoersConfig).toHaveBeenCalledWith('_default', expect.stringContaining('bob'))
    )
  })

  it('opens the step-up dialog when the save requires re-authentication', async () => {
    vi.mocked(api.saveSudoersConfig).mockRejectedValue(
      new ApiError(403, JSON.stringify({ error: 'stepup_required', auth_source: 'local' }))
    )
    render(<SudoersView />, { wrapper })

    await screen.findByText('alice')
    fireEvent.click(screen.getByText('alice'))
    fireEvent.change(screen.getByDisplayValue('alice'), { target: { value: 'bob' } })
    fireEvent.click(screen.getByRole('button', { name: /Save Changes/i }))
    fireEvent.click(await screen.findByRole('button', { name: 'Push change' }))

    expect(await screen.findByText("Confirm it's you")).toBeInTheDocument()
  })
})
