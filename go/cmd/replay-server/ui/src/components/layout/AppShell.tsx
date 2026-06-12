import { useState, useEffect } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { fetchMe } from '@/api/config'
import { fetchApprovals } from '@/api/approvals'
import { cn } from '@/lib/utils'
import { User, LogOut, Sun, Moon } from 'lucide-react'

function useTheme() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    return (localStorage.getItem('sudo-replay-theme') as 'dark' | 'light') || 'dark'
  })
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('sudo-replay-theme', theme)
  }, [theme])
  const toggle = () => setTheme(t => t === 'dark' ? 'light' : 'dark')
  return { theme, toggle }
}

const tabs = [
  { to: '/',          label: 'Sessions'  },
  { to: '/reports',   label: 'Reports'   },
  { to: '/policy',    label: 'Policy'    },
  { to: '/config',    label: 'Config'    },
  { to: '/approvals', label: 'Approvals' },
]

export function AppShell({ children }: { children: React.ReactNode }) {
  const { data: me } = useQuery({ queryKey: ['me'], queryFn: fetchMe })
  const { data: apprs } = useQuery({
    queryKey: ['approvals'],
    queryFn: fetchApprovals,
    refetchInterval: 15_000
  })
  const location = useLocation()
  const { theme, toggle: toggleTheme } = useTheme()

  const pendingCount = (apprs || []).filter(r => r.status === 'pending').length

  return (
    <div className="flex flex-col min-h-screen bg-bg text-text font-sans">
      <header className="border-b border-border bg-surface flex items-center justify-between px-4 h-[44px] shrink-0">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2">
            <img src="/logo-icon-72.svg" alt="sudo-logger" className="h-5 w-5" />
            <span className="font-medium text-[15px] text-white tracking-tight">sudo-replay</span>
          </div>
          <nav className="flex gap-1">
            {tabs.map(t => {
              const isActive = t.to === '/' ? location.pathname === '/' : location.pathname.startsWith(t.to)
              return (
                <NavLink
                  key={t.to}
                  to={t.to}
                  className={cn(
                    'px-3 py-1 text-[13px] rounded transition-colors font-medium border border-transparent flex items-center gap-2',
                    isActive
                      ? 'bg-green-dim text-green border-green/50'
                      : 'text-text-dim hover:text-text-sub hover:bg-card-hover',
                  )}
                >
                  {t.label}
                  {t.label === 'Approvals' && pendingCount > 0 && (
                    <span className="bg-red text-white text-[10px] font-bold rounded-full px-1.5 py-0.5 animate-pulse min-w-[18px] text-center">
                       {pendingCount}
                    </span>
                  )}
                </NavLink>
              )
            })}
          </nav>
        </div>
        <div className="flex items-center gap-4 text-xs text-text-dim">
          <label className="flex items-center gap-1.5 cursor-pointer hover:text-text-sub transition-colors">
            <input
              type="checkbox"
              className="accent-green cursor-pointer"
              defaultChecked={localStorage.getItem('sudo-replay-autoplay') !== 'false'}
              onChange={e => localStorage.setItem('sudo-replay-autoplay', String(e.target.checked))}
            />
            autoplay
          </label>

          <div className="h-4 w-px bg-border-mid" />

          <button
            onClick={toggleTheme}
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            className="flex items-center justify-center w-7 h-7 border border-border rounded hover:border-border-mid hover:text-text-sub transition-colors"
          >
            {theme === 'dark' ? <Sun size={13} /> : <Moon size={13} />}
          </button>

          <div className="h-4 w-px bg-border-mid" />

          {me && (
            <div className="flex items-center gap-2 text-text-sub font-mono">
              <User size={14} className="text-text-dim" />
              <span>{me.username}</span>
              <span className="text-[10px] bg-card border border-border px-1 rounded text-text-dim uppercase">{me.role}</span>
            </div>
          )}

          <a href="/oauth2/sign_out" className="flex items-center gap-1.5 hover:text-red transition-colors group">
            <LogOut size={14} className="text-text-dim group-hover:text-red" />
            Sign out
          </a>
        </div>
      </header>
      <main className="flex-1 overflow-hidden bg-bg">{children}</main>
    </div>
  )
}
