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
    <div className="flex h-[calc(100vh-[44px])]">
      <SessionList selectedTsid={selected?.tsid ?? null} onSelect={onSelect} />
      <div className="flex-1 overflow-hidden bg-bg">
        {selected ? (
          <TerminalPlayer session={selected} key={selected.tsid} />
        ) : (
          <div className="flex h-full items-center justify-center p-8">
            <div className="w-[600px] text-text-dim font-mono text-[13px]">
              <div className="mb-8">sudo-replay — select a session from the sidebar</div>
              <div className="mb-4 text-text font-bold">Keyboard shortcuts:</div>
              <div className="grid grid-cols-[100px_1fr] gap-y-2">
                <div className="text-blue">Space</div><div>play / pause</div>
                <div className="text-blue">→ / ←</div><div>seek ±5 seconds</div>
                <div className="text-blue">R</div><div>restart session</div>
                <div className="text-blue">/</div><div>focus search</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
