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
    <div className="flex flex-col min-h-screen bg-zinc-950 text-zinc-300 font-sans">
      <header className="border-b border-zinc-800 bg-[#0f1117] flex items-center justify-between px-4 h-[44px] shrink-0">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <img src="/logo-icon-72.svg" alt="sudo-logger" className="h-5 w-5" />
            <span className="font-medium text-[15px] text-zinc-100 tracking-tight">sudo-replay</span>
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
                      ? 'bg-[#1a7f37] text-white border-[#238636]/50' // green-ish theme for active
                      : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800',
                  )
                }
              >
                {t.label}
              </NavLink>
            ))}
          </nav>
        </div>
        <div className="flex items-center gap-4 text-xs text-zinc-500">
          <label className="flex items-center gap-2 cursor-pointer hover:text-zinc-300 transition-colors">
            <input type="checkbox" className="accent-[#1a7f37] cursor-pointer" defaultChecked />
            autoplay
          </label>
          <a href="/oauth2/sign_out" className="flex items-center gap-1 hover:text-red-400 transition-colors">
            Sign out
          </a>
        </div>
      </header>
      <main className="flex-1 overflow-hidden bg-[#09090f]">{children}</main>
    </div>
  )
}
