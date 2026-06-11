import { NavLink } from 'react-router-dom'
import { cn } from '@/lib/utils'

const tabs = [
  { to: '/',          label: 'Sessions'  },
  { to: '/reports',   label: 'Reports'   },
  { to: '/policy',    label: 'Policy'    },
  { to: '/config',    label: 'Config'    },
  { to: '/approvals', label: 'Approvals' },
]

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex flex-col min-h-screen bg-zinc-50 dark:bg-zinc-950">
      <header className="border-b border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900">
        <div className="flex items-center gap-6 px-4 h-12">
          <img src="/logo-icon-72.svg" alt="sudo-logger" className="h-6 w-6" />
          <nav className="flex gap-1">
            {tabs.map(t => (
              <NavLink
                key={t.to}
                to={t.to}
                end={t.to === '/'}
                className={({ isActive }) =>
                  cn(
                    'px-3 py-1.5 text-sm rounded-md transition-colors',
                    isActive
                      ? 'bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100 font-medium'
                      : 'text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100',
                  )
                }
              >
                {t.label}
              </NavLink>
            ))}
          </nav>
        </div>
      </header>
      <main className="flex-1 overflow-hidden">{children}</main>
    </div>
  )
}
