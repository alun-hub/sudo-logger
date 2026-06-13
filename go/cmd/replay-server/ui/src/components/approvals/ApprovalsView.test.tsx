import { render, screen } from '@testing-library/react'
import { ApprovalsView } from './ApprovalsView'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import * as api from '@/api/approvals'
import { vi, describe, it, expect } from 'vitest'

vi.mock('@/api/approvals', () => ({
  fetchApprovals: vi.fn(),
  approveRequest: vi.fn(),
  denyRequest: vi.fn(),
}))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false },
  },
})

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
)

describe('ApprovalsView', () => {
  it('renders pending approvals', async () => {
    vi.mocked(api.fetchApprovals).mockResolvedValue([
      { id: '1', user: 'alice', host: 'host1', command: 'ls', status: 'pending', submitted_at: new Date().toISOString() }
    ])

    render(<ApprovalsView />, { wrapper })

    expect(await screen.findByText('alice')).toBeInTheDocument()
    expect(screen.getByText(/host1/)).toBeInTheDocument()
    expect(screen.getByText('ls')).toBeInTheDocument()
  })
})
