import { render, screen, fireEvent } from '@testing-library/react'
import { ReportsView } from './ReportsView'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import * as api from '@/api/reports'
import { vi, describe, it, expect, beforeEach } from 'vitest'

vi.mock('@/api/reports', () => ({
  fetchReport: vi.fn(),
  fetchAccessLog: vi.fn(),
}))

const navigateSpy = vi.fn()
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return { ...actual, useNavigate: () => navigateSpy }
})

// ReportsView is mounted at <Route path="/reports/*"> in App.tsx (its own
// <Routes> uses paths relative to that match) -- replicate the same nesting
// here rather than rendering it bare, or the relative "summary"/"anomalies"
// routes won't resolve against a /reports/... pathname.
function renderAt(path: string, me?: { role: string; permissions: string[] }) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  if (me) queryClient.setQueryData(['me'], me)
  render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/reports/*" element={<ReportsView />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  )
}

const baseReport = {
  summary: {
    total_sessions: 42, unique_users: 3, unique_hosts: 2,
    incomplete_sessions: 1, long_sessions: 0, high_risk_sessions: 2, critical_sessions: 0,
    period_from: 0, period_to: 0,
  },
  per_user: [
    { user: 'alice', sessions: 10, hosts: 2, host_counts: [], avg_duration: 120, top_commands: ['ls'], incomplete: 1, long_sessions: 0, high_risk: 1, critical: 0 },
  ],
  anomalies: [
    { kind: 'root_shell', tsid: 'alice/host1_1', user: 'alice', host: 'host1', command: 'bash', start_time: 1000, duration: 30, detail: 'direct root shell', risk_score: 80 },
  ],
}

beforeEach(() => {
  navigateSpy.mockClear()
  vi.mocked(api.fetchReport).mockResolvedValue(baseReport as never)
  vi.mocked(api.fetchAccessLog).mockResolvedValue([])
})

describe('ReportsView', () => {
  it('renders summary stats and the per-user table', async () => {
    renderAt('/reports/summary')

    expect(await screen.findByText('Total Sessions')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByText('alice')).toBeInTheDocument()
  })

  it('renders anomalies and navigates to the session on row click', async () => {
    renderAt('/reports/anomalies')

    const cmd = await screen.findByText('bash')
    fireEvent.click(cmd.closest('tr')!)
    expect(navigateSpy).toHaveBeenCalledWith('/?tsid=alice/host1_1')
  })

  it('hides the View Audit tab for a viewer without audit_log:read', async () => {
    renderAt('/reports/summary', { role: 'viewer', permissions: [] })
    await screen.findByText('Total Sessions')
    expect(screen.queryByText('View Audit')).not.toBeInTheDocument()
  })

  it('shows the access log for an admin on the audit tab', async () => {
    vi.mocked(api.fetchAccessLog).mockResolvedValue([
      { time: 1700000000, viewer: 'alice', tsid: 'alice/host1_1' },
    ])
    renderAt('/reports/audit', { role: 'admin', permissions: [] })

    expect(await screen.findByText('alice')).toBeInTheDocument()
    expect(screen.getByText('1 entries')).toBeInTheDocument()
  })
})
