# Task 03: AppShell + Sessions View (Terminal Replay)

## Context
The replay-server SPA has 5 tabs: Sessions, Reports, Policy, Config, Approvals.
This task implements the outer application shell (navbar, tab routing) and the
Sessions view — the most complex view, containing:
- A filterable session list with risk badges
- A terminal replay player using @xterm/xterm

The Go server proxies `/api` in dev (see vite.config.ts). In prod, the Go
server serves the built files and the API directly.

## Working directory
`/home/alun/sudo-logger/go/cmd/replay-server/ui`

## Prerequisites
- Task 01 (project setup) complete
- Task 02 (API layer + types) complete

## Install shadcn/ui components needed

```bash
npx shadcn@latest add button badge input select separator scroll-area
```

---

## Files to create

### src/components/layout/AppShell.tsx

Navigation bar with 5 tabs. Uses React Router NavLink.

```tsx
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
```

### src/App.tsx (with routing)

```tsx
import { Routes, Route, Navigate } from 'react-router-dom'
import { AppShell } from '@/components/layout/AppShell'
import { SessionsView } from '@/components/sessions/SessionsView'

// Lazy-loaded views (Tasks 04 and 05 will fill these in)
import { lazy, Suspense } from 'react'
const ReportsView   = lazy(() => import('@/components/reports/ReportsView').then(m => ({ default: m.ReportsView })))
const PolicyEditor  = lazy(() => import('@/components/policy/PolicyEditor').then(m => ({ default: m.PolicyEditor })))
const ConfigPanel   = lazy(() => import('@/components/config/ConfigPanel').then(m => ({ default: m.ConfigPanel })))
const ApprovalsView = lazy(() => import('@/components/approvals/ApprovalsView').then(m => ({ default: m.ApprovalsView })))

export default function App() {
  return (
    <AppShell>
      <Suspense fallback={<div className="p-8 text-zinc-400">Loading…</div>}>
        <Routes>
          <Route path="/"          element={<SessionsView />} />
          <Route path="/reports"   element={<ReportsView />} />
          <Route path="/policy"    element={<PolicyEditor />} />
          <Route path="/config"    element={<ConfigPanel />} />
          <Route path="/approvals" element={<ApprovalsView />} />
          <Route path="*"          element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </AppShell>
  )
}
```

### src/components/sessions/RiskBadge.tsx

```tsx
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { SessionInfo } from '@/types/session'

const colors: Record<SessionInfo['risk_level'], string> = {
  critical: 'bg-red-600 text-white',
  high:     'bg-orange-500 text-white',
  medium:   'bg-yellow-500 text-black',
  low:      'bg-blue-500 text-white',
  none:     'bg-zinc-200 text-zinc-700',
}

export function RiskBadge({ level }: { level: SessionInfo['risk_level'] }) {
  return (
    <Badge className={cn('text-xs font-semibold uppercase', colors[level])}>
      {level}
    </Badge>
  )
}
```

### src/components/sessions/SessionRow.tsx

```tsx
import { fmtDate, fmtDuration } from '@/lib/date'
import { RiskBadge } from './RiskBadge'
import { cn } from '@/lib/utils'
import type { SessionInfo } from '@/types/session'

interface Props {
  session: SessionInfo
  selected: boolean
  onClick: () => void
}

export function SessionRow({ session: s, selected, onClick }: Props) {
  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full text-left px-3 py-2 text-sm border-b border-zinc-100 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800/50 transition-colors',
        selected && 'bg-zinc-100 dark:bg-zinc-800',
      )}
    >
      <div className="flex items-center justify-between gap-2 mb-0.5">
        <span className="font-medium text-zinc-900 dark:text-zinc-100 truncate">
          {s.user}@{s.host}
        </span>
        <RiskBadge level={s.risk_level} />
      </div>
      <div className="text-zinc-500 dark:text-zinc-400 truncate text-xs">
        {s.command}
      </div>
      <div className="text-zinc-400 dark:text-zinc-500 text-xs mt-0.5 flex gap-2">
        <span>{fmtDate(s.start_time)}</span>
        <span>{fmtDuration(s.duration)}</span>
        {s.in_progress && <span className="text-emerald-500">● live</span>}
      </div>
    </button>
  )
}
```

### src/components/sessions/SessionList.tsx

```tsx
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchSessions } from '@/api/sessions'
import { SessionRow } from './SessionRow'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import type { SessionInfo } from '@/types/session'

interface Props {
  selectedTsid: string | null
  onSelect: (s: SessionInfo) => void
}

export function SessionList({ selectedTsid, onSelect }: Props) {
  const [q, setQ] = useState('')

  const { data, isPending, isError } = useQuery({
    queryKey: ['sessions', q],
    queryFn: () => fetchSessions({ q, limit: 100 }),
    refetchInterval: 15_000,
  })

  return (
    <div className="flex flex-col h-full border-r border-zinc-200 dark:border-zinc-800 w-72 shrink-0">
      <div className="p-2 border-b border-zinc-200 dark:border-zinc-800">
        <Input
          placeholder="Search…"
          value={q}
          onChange={e => setQ(e.target.value)}
          className="h-7 text-sm"
        />
      </div>
      <div className="flex-1 overflow-y-auto">
        {isPending && <p className="p-3 text-sm text-zinc-400">Loading…</p>}
        {isError  && <p className="p-3 text-sm text-red-500">Failed to load sessions</p>}
        {data?.sessions.map(s => (
          <SessionRow
            key={s.tsid}
            session={s}
            selected={s.tsid === selectedTsid}
            onClick={() => onSelect(s)}
          />
        ))}
      </div>
      {data && (
        <div className="p-2 text-xs text-zinc-400 border-t border-zinc-200 dark:border-zinc-800">
          {data.sessions.length} / {data.total} sessions
        </div>
      )}
    </div>
  )
}
```

### src/components/terminal/TerminalPlayer.tsx

The most complex component. Wraps xterm.js, fetches NDJSON events, implements
play/pause/scrubber.

```tsx
import { useEffect, useRef, useState, useCallback } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { fetchSessionEvents } from '@/api/sessions'
import { fmtDuration } from '@/lib/date'
import { Button } from '@/components/ui/button'
import type { SessionInfo } from '@/types/session'
import type { SessionEvent } from '@/types/session'
import '@xterm/xterm/css/xterm.css'

interface Props {
  session: SessionInfo
}

export function TerminalPlayer({ session }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const termRef      = useRef<Terminal | null>(null)
  const fitRef       = useRef<FitAddon | null>(null)
  const rafRef       = useRef<number>(0)

  const [events, setEvents]     = useState<SessionEvent[]>([])
  const [loading, setLoading]   = useState(false)
  const [playing, setPlaying]   = useState(false)
  const [elapsed, setElapsed]   = useState(0)    // seconds into session
  const [speed, setSpeed]       = useState(1)

  // Track playback state in refs (avoids stale closures in rAF loop)
  const playingRef  = useRef(false)
  const elapsedRef  = useRef(0)
  const speedRef    = useRef(1)
  const eventsRef   = useRef<SessionEvent[]>([])
  const eventIdxRef = useRef(0)
  const lastRafTs   = useRef<number>(0)

  // Init xterm
  useEffect(() => {
    if (!containerRef.current) return
    const term = new Terminal({
      theme: { background: '#18181b', foreground: '#e4e4e7' },
      fontSize: 13,
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
      cursorBlink: false,
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(containerRef.current)
    fit.fit()
    termRef.current = term
    fitRef.current  = fit

    const observer = new ResizeObserver(() => fit.fit())
    observer.observe(containerRef.current)

    return () => {
      observer.disconnect()
      term.dispose()
    }
  }, [])

  // Load events when session changes
  useEffect(() => {
    setLoading(true)
    setPlaying(false)
    playingRef.current = false
    setElapsed(0)
    elapsedRef.current = 0
    eventIdxRef.current = 0
    termRef.current?.clear()

    fetchSessionEvents(session.tsid)
      .then(evs => {
        setEvents(evs)
        eventsRef.current = evs
      })
      .finally(() => setLoading(false))
  }, [session.tsid])

  // rAF playback loop
  const tick = useCallback((ts: number) => {
    if (!playingRef.current) return
    const dt = lastRafTs.current ? (ts - lastRafTs.current) / 1000 * speedRef.current : 0
    lastRafTs.current = ts
    elapsedRef.current += dt
    setElapsed(elapsedRef.current)

    // Write all events up to elapsedRef.current
    const evs = eventsRef.current
    while (
      eventIdxRef.current < evs.length &&
      evs[eventIdxRef.current].t <= elapsedRef.current
    ) {
      const ev = evs[eventIdxRef.current++]
      if ((ev.type === 'o' || ev.type === 'i') && ev.data) {
        const bytes = atob(ev.data)
        termRef.current?.write(bytes)
      } else if (ev.type === 'resize' && ev.cols && ev.rows) {
        termRef.current?.resize(ev.cols, ev.rows)
      }
    }

    // Stop at end
    if (eventIdxRef.current >= evs.length && evs.length > 0) {
      setPlaying(false)
      playingRef.current = false
      return
    }

    rafRef.current = requestAnimationFrame(tick)
  }, [])

  const play = useCallback(() => {
    playingRef.current = true
    lastRafTs.current  = 0
    setPlaying(true)
    rafRef.current = requestAnimationFrame(tick)
  }, [tick])

  const pause = useCallback(() => {
    playingRef.current = false
    cancelAnimationFrame(rafRef.current)
    setPlaying(false)
  }, [])

  const restart = useCallback(() => {
    pause()
    elapsedRef.current  = 0
    eventIdxRef.current = 0
    setElapsed(0)
    termRef.current?.clear()
    play()
  }, [pause, play])

  const seek = useCallback((targetSecs: number) => {
    pause()
    termRef.current?.clear()
    elapsedRef.current  = targetSecs
    eventIdxRef.current = 0
    setElapsed(targetSecs)

    // Replay all events up to targetSecs instantly
    const evs = eventsRef.current
    while (
      eventIdxRef.current < evs.length &&
      evs[eventIdxRef.current].t <= targetSecs
    ) {
      const ev = evs[eventIdxRef.current++]
      if ((ev.type === 'o' || ev.type === 'i') && ev.data) {
        termRef.current?.write(atob(ev.data))
      }
    }
  }, [pause])

  const totalDuration = events.length > 0 ? events[events.length - 1].t : session.duration

  return (
    <div className="flex flex-col h-full bg-zinc-900 text-zinc-100">
      {/* Terminal */}
      <div ref={containerRef} className="flex-1 overflow-hidden p-1" />

      {/* Controls */}
      <div className="flex items-center gap-2 px-3 py-2 border-t border-zinc-700 text-sm">
        {loading ? (
          <span className="text-zinc-400 text-xs">Loading events…</span>
        ) : (
          <>
            <Button size="sm" variant="ghost" onClick={restart} className="text-zinc-300 h-7 px-2">↩</Button>
            <Button size="sm" variant="ghost" onClick={playing ? pause : play} className="text-zinc-300 h-7 px-2">
              {playing ? '⏸' : '▶'}
            </Button>
            <input
              type="range"
              min={0}
              max={totalDuration}
              step={0.1}
              value={elapsed}
              onChange={e => seek(Number(e.target.value))}
              className="flex-1 h-1 accent-zinc-300"
            />
            <span className="text-zinc-400 font-mono text-xs w-28 text-right">
              {fmtDuration(elapsed)} / {fmtDuration(totalDuration)}
            </span>
            <select
              value={speed}
              onChange={e => { speedRef.current = Number(e.target.value); setSpeed(Number(e.target.value)) }}
              className="bg-zinc-800 text-zinc-300 text-xs rounded px-1 h-7"
            >
              {[0.25, 0.5, 1, 2, 5, 10].map(s => (
                <option key={s} value={s}>{s}×</option>
              ))}
            </select>
          </>
        )}
      </div>
    </div>
  )
}
```

### src/components/sessions/SessionsView.tsx

```tsx
import { useState } from 'react'
import { SessionList } from './SessionList'
import { TerminalPlayer } from '@/components/terminal/TerminalPlayer'
import type { SessionInfo } from '@/types/session'

export function SessionsView() {
  const [selected, setSelected] = useState<SessionInfo | null>(null)

  return (
    <div className="flex h-[calc(100vh-3rem)]">
      <SessionList selectedTsid={selected?.tsid ?? null} onSelect={setSelected} />
      <div className="flex-1 overflow-hidden">
        {selected ? (
          <TerminalPlayer session={selected} />
        ) : (
          <div className="flex h-full items-center justify-center text-zinc-400 text-sm">
            Select a session to replay
          </div>
        )}
      </div>
    </div>
  )
}
```

### Stub views for lazy routes (Tasks 04 and 05 will replace these)

Create these minimal stubs so App.tsx compiles:

**src/components/reports/ReportsView.tsx**
```tsx
export function ReportsView() {
  return <div className="p-8 text-zinc-400">Reports — coming in Task 04</div>
}
```

**src/components/policy/PolicyEditor.tsx**
```tsx
export function PolicyEditor() {
  return <div className="p-8 text-zinc-400">Policy — coming in Task 04</div>
}
```

**src/components/config/ConfigPanel.tsx**
```tsx
export function ConfigPanel() {
  return <div className="p-8 text-zinc-400">Config — coming in Task 05</div>
}
```

**src/components/approvals/ApprovalsView.tsx**
```tsx
export function ApprovalsView() {
  return <div className="p-8 text-zinc-400">Approvals — coming in Task 05</div>
}
```

---

## Verification

```bash
cd go/cmd/replay-server/ui
npm run lint         # 0 errors

npm run dev
# → open http://localhost:5173
# → navbar shows 5 tabs
# → Sessions tab: session list loads from /api/sessions
# → click a session with has_io=true → terminal plays back
```

## Output for next task
Sessions view is complete. Task 04 implements Reports and Policy views.
