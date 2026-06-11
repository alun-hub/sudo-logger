import { useState, type ChangeEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchSessions } from '@/api/sessions'
import { SessionRow } from './SessionRow'
import { Input } from '@/components/ui/input'
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
          onChange={(e: ChangeEvent<HTMLInputElement>) => setQ(e.target.value)}
          className="h-7 text-sm"
        />
      </div>
      <div className="flex-1 overflow-y-auto">
        {isPending && <p className="p-3 text-sm text-zinc-400">Loading…</p>}
        {isError && <p className="p-3 text-sm text-red-500">Failed to load sessions</p>}
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
