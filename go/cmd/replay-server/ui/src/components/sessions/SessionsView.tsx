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
