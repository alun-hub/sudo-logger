import { useState, type ChangeEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchSessions } from '@/api/sessions'
import { SessionRow } from './SessionRow'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import type { SessionInfo } from '@/types/session'

interface Props {
  selectedTsid: string | null
  onSelect: (s: SessionInfo) => void
}

export function SessionList({ selectedTsid, onSelect }: Props) {
  const [q, setQ] = useState('')
  const [sort, setSort] = useState('Date')

  const { data, isPending, isError } = useQuery({
    queryKey: ['sessions', q],
    queryFn: () => fetchSessions({ q, limit: 100 }),
    refetchInterval: 15_000,
  })

  return (
    <div className="flex flex-col h-full border-r border-[#1e2230] w-[320px] shrink-0 bg-[#0f1117]">
      <div className="p-2.5 border-b border-[#1e2230] flex flex-col gap-2">
        <div className="relative">
          <svg className="absolute left-3 top-[8px] text-[#4a5068]" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          <Input
            placeholder="Search user host command — space separated AND"
            value={q}
            onChange={(e: ChangeEvent<HTMLInputElement>) => setQ(e.target.value)}
            className="w-full h-[32px] bg-[#161921] border-[#1e2230] text-[#d4daf0] text-[13px] pl-9 rounded-[5px] focus:border-[#00e87a] placeholder:text-[#4a5068]"
          />
        </div>

        <div className="flex gap-1">
          {['Date ↓', 'User', 'Host', 'Dur', 'Risk'].map(s => (
            <button
              key={s}
              onClick={() => setSort(s)}
              className={cn(
                "flex-1 text-[11px] font-medium py-1 rounded-[5px] border transition-colors",
                sort === s
                  ? "bg-[#003d20] border-[#00e87a] text-[#00e87a]"
                  : "bg-transparent border-[#1e2230] text-[#4a5068] hover:border-[#2a2f42] hover:text-[#8890a8]"
              )}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1">
          <Input type="date" className="h-[28px] text-[11px] bg-[#161921] border-[#1e2230] text-[#8890a8] flex-1 rounded-[5px]" />
          <span className="text-[#4a5068] text-[11px] px-1">→</span>
          <Input type="date" className="h-[28px] text-[11px] bg-[#161921] border-[#1e2230] text-[#8890a8] flex-1 rounded-[5px]" />
          <button className="text-[#4a5068] hover:text-[#ff5f6d] px-2 text-[14px]">×</button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto overflow-x-hidden" style={{ scrollbarWidth: 'thin', scrollbarColor: '#2a2f42 transparent' }}>
        {isPending && <p className="p-3 text-[13px] text-[#4a5068]">Loading…</p>}
        {isError && <p className="p-3 text-[13px] text-[#ff5f6d]">Failed to load sessions</p>}
        {data?.sessions?.map(s => (
          <SessionRow
            key={s.tsid}
            session={s}
            selected={s.tsid === selectedTsid}
            onClick={() => onSelect(s)}
          />
        ))}
        {data && (
          <div className="p-3 text-center">
            <button className="text-[#4a5068] hover:text-[#d4daf0] text-[12px] font-medium transition-colors">
              Load more
            </button>
          </div>
        )}
      </div>
      {data && (
        <div className="p-2 text-[11px] text-[#4a5068] border-t border-[#1e2230] bg-[#0f1117]">
          {data.sessions.length} / {data.total} sessions
        </div>
      )}
    </div>
  )
}
