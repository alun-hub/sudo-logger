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
    <div className="flex flex-col min-h-screen bg-bg text-text font-sans">
      <header className="border-b border-border bg-surface flex items-center justify-between px-4 h-[44px] shrink-0">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <img src="/logo-icon-72.svg" alt="sudo-logger" className="h-5 w-5" />
            <span className="font-medium text-[15px] text-white tracking-tight">sudo-replay</span>
          </div>
          <nav className="flex gap-1">
            {tabs.map(t => (
              <NavLink
                key={t.to}
                to={t.to}
                end={t.to === '/'}
                className={({ isActive }) =>
                  cn(
                    'px-3 py-1 text-[13px] rounded transition-colors font-medium border border-transparent',
                    isActive
                      ? 'bg-green-dim text-green border-green/50'
                      : 'text-text-dim hover:text-text-sub hover:bg-card-hover',
                  )
                }
              >
                {t.label}
              </NavLink>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-4 text-xs text-text-dim">
          <label className="flex items-center gap-2 cursor-pointer hover:text-text-sub transition-colors">
            <input
              type="checkbox"
              className="accent-green cursor-pointer"
              defaultChecked={localStorage.getItem('sudo-replay-autoplay') !== 'false'}
              onChange={e => localStorage.setItem('sudo-replay-autoplay', String(e.target.checked))}
            />
            autoplay
          </label>
          <a href="/oauth2/sign_out" className="flex items-center gap-1 hover:text-red transition-colors">
            Sign out
          </a>
        </div>
      </header>
      <main className="flex-1 overflow-hidden bg-bg">{children}</main>
    </div>
  )
}
