import { render, screen } from '@testing-library/react'
import { ConfigPanel } from './ConfigPanel'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect } from 'vitest'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false },
  },
})

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <MemoryRouter initialEntries={['/config/jit']}>
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  </MemoryRouter>
)

describe('ConfigPanel', () => {
  it('renders all configuration tabs', () => {
    render(<ConfigPanel />, { wrapper })

    expect(screen.getByText('SIEM Forwarding')).toBeInTheDocument()
    expect(screen.getByText('System Auth')).toBeInTheDocument()
    expect(screen.getByText('Users & Roles')).toBeInTheDocument()
    expect(screen.getByText('Data Retention')).toBeInTheDocument()
    expect(screen.getByText('Process Sandbox')).toBeInTheDocument()
    expect(screen.getByText('JIT / Approvals')).toBeInTheDocument()
  })
})
