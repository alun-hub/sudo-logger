import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { SessionList } from './SessionList'
import { TerminalPlayer } from '../terminal/TerminalPlayer'
import type { SessionInfo } from '@/types/session'
import { fetchSessions } from '@/api/sessions'

export function SessionsView() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [selected, setSelected] = useState<SessionInfo | null>(null)
  const tsidParam = searchParams.get('tsid')

  useEffect(() => {
    if (tsidParam && (!selected || selected.tsid !== tsidParam)) {
      fetchSessions({ q: tsidParam, limit: 1 }).then(res => {
        if (res.sessions.length > 0) setSelected(res.sessions[0])
      })
    }
  }, [tsidParam])

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.code === 'Slash') {
        const tag = (e.target as HTMLElement).tagName
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
        e.preventDefault()
        document.getElementById('global-search')?.focus()
      }
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [])

  const onSelect = (s: SessionInfo) => {
    setSelected(s)
    if (tsidParam !== s.tsid) {
       setSearchParams({ tsid: s.tsid })
    }
  }

  return (
    <div className="flex h-[calc(100vh-48px)] overflow-hidden">
      <SessionList selectedTsid={selected?.tsid ?? null} onSelect={onSelect} />
      <div className="flex-1 overflow-hidden bg-bg relative">
        {selected ? (
          <TerminalPlayer session={selected} key={selected.tsid} />
        ) : (
          <div className="flex h-full items-center justify-center p-8 bg-bg transition-colors duration-200">
            <div className="max-w-[600px] text-text-dim font-mono text-[13px] bg-card/20 p-8 rounded-lg border border-border/50">
              <div className="mb-8 text-[15px] flex items-center gap-3">
                 <img src="/logo-icon-72.svg" alt="logo" className="w-8 h-8 opacity-50" />
                 <span>sudo-replay — select a session from the sidebar to begin auditing</span>
              </div>
              <div className="mb-4 text-text font-bold uppercase tracking-widest text-[11px] border-b border-border pb-1">Keyboard shortcuts</div>
              <div className="grid grid-cols-[140px_1fr] gap-y-3">
                <div className="text-green/60 uppercase text-[10px] tracking-widest col-span-2 mt-1">Player</div>
                <div className="text-green font-bold">Space</div><div className="text-text-sub">play / pause</div>
                <div className="text-green font-bold">← / →</div><div className="text-text-sub">seek backward / forward</div>
                <div className="text-green font-bold">Shift+← / →</div><div className="text-text-sub">seek (longer step)</div>
                <div className="text-green font-bold">0 – 9</div><div className="text-text-sub">jump to 0–90% of session</div>
                <div className="text-green font-bold">f</div><div className="text-text-sub">fullscreen</div>
                <div className="text-green font-bold">m</div><div className="text-text-sub">mute / unmute</div>
                <div className="text-green font-bold">? </div><div className="text-text-sub">show player shortcuts</div>
                <div className="text-green/60 uppercase text-[10px] tracking-widest col-span-2 mt-2">Navigation</div>
                <div className="text-green font-bold">/</div><div className="text-text-sub">focus session search</div>
                <div className="text-green font-bold">↑ / ↓</div><div className="text-text-sub">navigate sessions</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
