import { render, screen } from '@testing-library/react'
import { ConfigPanel } from './ConfigPanel'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect } from 'vitest'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: false },
  },
})

const wrapper = ({ children }: { children: React.ReactNode }) => (
  <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
)

describe('ConfigPanel', () => {
  it('renders all configuration tabs', () => {
    render(<ConfigPanel />, { wrapper })

    expect(screen.getByText('SIEM')).toBeInTheDocument()
    expect(screen.getByText('Auth')).toBeInTheDocument()
    expect(screen.getByText('Users & Roles')).toBeInTheDocument()
    expect(screen.getByText('Retention')).toBeInTheDocument()
    expect(screen.getByText('Sandbox')).toBeInTheDocument()
    expect(screen.getByText('JIT / Approvals')).toBeInTheDocument()
  })
})
