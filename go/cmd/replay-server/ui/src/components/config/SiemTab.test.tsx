import { render, screen } from '@testing-library/react'
import { SiemTab } from './SiemTab'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import * as api from '@/api/config'
import { vi, describe, it, expect } from 'vitest'

vi.mock('@/api/config', () => ({
  fetchSiemConfig: vi.fn(),
  saveSiemConfig: vi.fn(),
  uploadSiemCert: vi.fn(),
}))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false },
  },
})

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
)

describe('SiemTab', () => {
  it('renders siem configuration fields', async () => {
    vi.mocked(api.fetchSiemConfig).mockResolvedValue({ type: 'splunk', url: 'http://splunk:8088', token: 'secret' })

    render(<SiemTab />, { wrapper })

    expect(await screen.findByDisplayValue('http://splunk:8088')).toBeInTheDocument()
    expect(screen.getByText('SIEM Integration')).toBeInTheDocument()
  })
})
