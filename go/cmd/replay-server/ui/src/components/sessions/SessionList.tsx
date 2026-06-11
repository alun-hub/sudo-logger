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
  const [sort, setSort] = useState('Date ↓')
  const [from, setFrom] = useState('')
  const [to, setTo]     = useState('')

  const fromTs = from ? Math.floor(new Date(from).getTime() / 1000) : undefined
  const toTs   = to   ? Math.floor(new Date(to).getTime() / 1000) : undefined

  const { data, isPending, isError } = useQuery({
    queryKey: ['sessions', q, sort, fromTs, toTs],
    queryFn: () => fetchSessions({
      q,
      sort: sort.replace(' ↓', '').toLowerCase(),
      from: fromTs,
      to: toTs,
      limit: 100
    }),
    refetchInterval: 15_000,
  })

  return (
    <div className="flex flex-col h-full border-r border-border w-[320px] shrink-0 bg-surface">
      <div className="p-2.5 border-b border-border flex flex-col gap-2">
        <div className="relative">
          <svg className="absolute left-3 top-[8px] text-text-dim" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          <Input
            placeholder="Search user host command — space separated AND"
            value={q}
            onChange={(e: ChangeEvent<HTMLInputElement>) => setQ(e.target.value)}
            className="w-full h-[32px] bg-card border-border text-text text-[13px] pl-9 rounded-[5px] focus:border-green placeholder:text-text-dim"
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
                  ? "bg-green-dim border-green text-green"
                  : "bg-transparent border-border text-text-dim hover:border-border-mid hover:text-text-sub"
              )}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-1">
          <Input
            type="date"
            value={from}
            onChange={e => setFrom(e.target.value)}
            className="h-[28px] text-[11px] bg-card border-border text-text-sub flex-1 rounded-[5px] outline-none"
          />
          <span className="text-text-dim text-[11px] px-1">→</span>
          <Input
            type="date"
            value={to}
            onChange={e => setTo(e.target.value)}
            className="h-[28px] text-[11px] bg-card border-border text-text-sub flex-1 rounded-[5px] outline-none"
          />
          <button
            onClick={() => { setFrom(''); setTo('') }}
            className="text-text-dim hover:text-red px-2 text-[14px]"
          >×</button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto overflow-x-hidden" style={{ scrollbarWidth: 'thin' }}>
        {isPending && <p className="p-3 text-[13px] text-text-dim">Loading…</p>}
        {isError && <p className="p-3 text-[13px] text-red">Failed to load sessions</p>}
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
            <button className="text-text-dim hover:text-text text-[12px] font-medium transition-colors">
              Load more
            </button>
          </div>
        )}
      </div>
      {data && (
        <div className="p-2 text-[11px] text-text-dim border-t border-border bg-surface">
          {data.sessions.length} / {data.total} sessions
        </div>
      )}
    </div>
  )
}
