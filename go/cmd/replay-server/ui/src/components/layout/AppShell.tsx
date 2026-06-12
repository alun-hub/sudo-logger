import { useState, useEffect } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { fetchMe } from '@/api/config'
import { fetchApprovals } from '@/api/approvals'
import { cn } from '@/lib/utils'
import { User, LogOut, Sun, Moon } from 'lucide-react'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'

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
  const [showHelp, setShowHelp] = useState(false)

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if (e.key === '?') setShowHelp(v => !v)
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [])

  return (
    <div className="flex flex-col h-screen bg-bg text-text font-sans overflow-hidden transition-colors duration-200">
      <header className="border-b border-border bg-surface flex items-center justify-between px-4 h-[48px] shrink-0 z-50 shadow-sm">
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-2.5">
            <img src="/logo-icon-72.svg" alt="sudo-logger" className="h-6 w-6" />
            <span className="font-bold text-[16px] text-foreground tracking-tight uppercase">sudo-replay</span>
          </div>
          <nav className="flex gap-2">
            {tabs.map(t => {
              const isActive = t.to === '/' ? location.pathname === '/' : location.pathname.startsWith(t.to)
              return (
                <NavLink
                  key={t.to}
                  to={t.to}
                  className={cn(
                    'px-4 py-1.5 text-[13px] rounded-[4px] transition-all font-semibold border-b-2 border-transparent hover:text-foreground',
                    isActive
                      ? 'text-green border-green bg-green/5'
                      : 'text-text-dim hover:bg-card-hover',
                  )}
                >
                  {t.label}
                  {t.label === 'Approvals' && pendingCount > 0 && (
                    <span className="ml-2 bg-red text-white text-[10px] font-bold rounded-full px-1.5 py-0.5 animate-pulse min-w-[18px] text-center">
                       {pendingCount}
                    </span>
                  )}
                </NavLink>
              )
            })}
          </nav>
        </div>
        <div className="flex items-center gap-5 text-xs text-text-dim">
          <label className="flex items-center gap-2 cursor-pointer hover:text-green transition-colors font-medium">
            <div className="relative">
              <input
                type="checkbox"
                className="sr-only peer"
                defaultChecked={localStorage.getItem('sudo-replay-autoplay') !== 'false'}
                onChange={e => localStorage.setItem('sudo-replay-autoplay', String(e.target.checked))}
              />
              <div className="w-8 h-4 bg-card rounded-full border border-border peer-checked:bg-green peer-checked:border-green transition-colors"></div>
              <div className="absolute left-[2px] top-[2px] w-3 h-3 bg-white rounded-full transition-transform peer-checked:translate-x-4"></div>
            </div>
            <span className="peer-checked:text-green flex items-center gap-1">
               {localStorage.getItem('sudo-replay-autoplay') !== 'false' && <span className="w-1.5 h-1.5 bg-green rounded-full animate-pulse" />}
               autoplay
            </span>
          </label>

          <div className="h-5 w-px bg-border/50" />

          <button
            onClick={toggleTheme}
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            className="flex items-center justify-center w-7 h-7 border border-border rounded hover:border-border-mid hover:text-text-sub transition-colors"
          >
            {theme === 'dark' ? <Sun size={13} /> : <Moon size={13} />}
          </button>

          <div className="h-4 w-px bg-border-mid" />

          <button
            onClick={() => setShowHelp(true)}
            title="Keyboard shortcuts"
            className="flex items-center justify-center w-7 h-7 border border-border rounded hover:border-border-mid hover:text-text-sub transition-colors font-bold text-[13px]"
          >?</button>

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

      <Dialog open={showHelp} onOpenChange={setShowHelp}>
        <DialogContent className="max-w-md bg-surface border-border text-text">
          <DialogHeader>
            <DialogTitle className="text-[15px]">Keyboard Shortcuts</DialogTitle>
          </DialogHeader>
          <div className="space-y-4 pt-2 text-[13px]">
            <Section title="Player">
              <KbdRow keys={['Space']}      desc="Play / pause" />
              <KbdRow keys={['←']}          desc="Seek back 5 seconds" />
              <KbdRow keys={['→']}          desc="Seek forward 5 seconds" />
            </Section>
            <Section title="Session list">
              <KbdRow keys={['↑', '↓']}    desc="Navigate sessions" />
            </Section>
            <Section title="General">
              <KbdRow keys={['?']}          desc="Show this help" />
            </Section>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-2">{title}</div>
      <div className="space-y-1.5">{children}</div>
    </div>
  )
}

function KbdRow({ keys, desc }: { keys: string[]; desc: string }) {
  return (
    <div className="flex items-center gap-3">
      <div className="flex gap-1 shrink-0">
        {keys.map(k => (
          <kbd key={k} className="px-1.5 py-0.5 rounded-[3px] bg-card border border-border font-mono text-[11px] text-text-sub">{k}</kbd>
        ))}
      </div>
      <span className="text-text-sub">{desc}</span>
    </div>
  )
}
