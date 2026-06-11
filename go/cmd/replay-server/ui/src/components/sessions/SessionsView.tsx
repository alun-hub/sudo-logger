import { useState } from 'react'
import { SessionList } from './SessionList'
import { TerminalPlayer } from '@/components/terminal/TerminalPlayer'
import type { SessionInfo } from '@/types/session'

export function SessionsView() {
  const [selected, setSelected] = useState<SessionInfo | null>(null)

  return (
    <div className="flex h-[calc(100vh-[44px])]">
      <SessionList selectedTsid={selected?.tsid ?? null} onSelect={setSelected} />
      <div className="flex-1 overflow-hidden bg-bg">
        {selected ? (
          <TerminalPlayer session={selected} />
        ) : (
          <div className="flex h-full items-center justify-center p-8">
            <div className="w-[600px] text-text-dim font-mono text-[13px]">
              <div className="mb-8">sudo-replay — select a session from the sidebar</div>
              <div className="mb-4">Keyboard shortcuts:</div>
              <div className="grid grid-cols-[100px_1fr] gap-y-2">
                <div>Space</div><div>play / pause</div>
                <div>→ / ←</div><div>seek ±5 seconds</div>
                <div>R</div><div>restart</div>
                <div>/</div><div>focus search</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
