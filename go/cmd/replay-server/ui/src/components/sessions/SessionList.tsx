import { useState, useEffect, useRef, type ChangeEvent } from 'react'
import { useInfiniteQuery } from '@tanstack/react-query'
import { fetchSessions } from '@/api/sessions'
import { SessionRow } from './SessionRow'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import { useSessionStats } from '@/lib/sessionStats'
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

  const {
    data,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
    isPending,
    isError
  } = useInfiniteQuery({
    queryKey: ['sessions', q, sort, fromTs, toTs],
    queryFn: ({ pageParam }) => fetchSessions({
      q,
      sort: sort.replace(' ↓', '').toLowerCase(),
      from: fromTs,
      to: toTs,
      limit: 100,
      cursor: pageParam as string | undefined
    }),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (lastPage) => lastPage.cursor,
    refetchInterval: 15_000,
  })

  const sessions = data?.pages.flatMap(p => p.sessions) ?? []
  const total    = data?.pages[0]?.total ?? 0
  const listRef  = useRef<HTMLDivElement>(null)
  const { setStats } = useSessionStats()
  useEffect(() => { setStats(sessions.length, total) }, [sessions.length, total, setStats])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown') return
      e.preventDefault()
      if (!sessions.length) return
      const idx = selectedTsid ? sessions.findIndex(s => s.tsid === selectedTsid) : -1
      let next = idx
      if (e.key === 'ArrowDown') next = Math.min(idx + 1, sessions.length - 1)
      if (e.key === 'ArrowUp')   next = Math.max(idx - 1, 0)
      if (next !== idx && sessions[next]) {
        onSelect(sessions[next])
        listRef.current?.querySelectorAll('[data-tsid]')[next]?.scrollIntoView({ block: 'nearest' })
      }
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [sessions, selectedTsid, onSelect])

  return (
    <div className="flex flex-col h-full border-r border-border w-[380px] shrink-0 bg-bg z-40 shadow-xl shadow-black/10 transition-colors duration-200">
      <div className="p-3 border-b border-border bg-surface flex flex-col gap-3">
        <div className="relative group">
          <svg className="absolute left-3 top-[10px] text-text-dim group-focus-within:text-green transition-colors" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          <Input
            placeholder="Search sessions... ( / )"
            id="global-search"
            value={q}
            onChange={(e: ChangeEvent<HTMLInputElement>) => setQ(e.target.value)}
            className="w-full h-[36px] bg-card border-border text-text text-[13px] pl-10 rounded-[6px] focus:ring-1 focus:ring-green/50 focus:border-green placeholder:text-text-dim/60 transition-all"
          />
        </div>

        <div className="flex gap-1.5">
          {['Date ↓', 'User', 'Host', 'Dur', 'Risk'].map(s => (
            <button
              key={s}
              onClick={() => setSort(s)}
              className={cn(
                "flex-1 text-[11px] font-bold py-1.5 rounded-[4px] border uppercase tracking-wider transition-all",
                sort === s
                  ? "bg-green border-green text-primary-foreground shadow-[0_0_10px_rgba(0,232,122,0.2)]"
                  : "bg-transparent border-border text-text-dim hover:border-border-mid hover:text-text-sub"
              )}
            >
              {s}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <div className="relative flex-1">
             <Input
               type="date"
               value={from}
               onChange={e => setFrom(e.target.value)}
               className="h-[30px] text-[11px] bg-card border-border text-text-sub w-full rounded-[4px] outline-none px-2 focus:border-green transition-colors"
             />
          </div>
          <span className="text-text-dim text-[11px] font-bold">→</span>
          <div className="relative flex-1">
             <Input
               type="date"
               value={to}
               onChange={e => setTo(e.target.value)}
               className="h-[30px] text-[11px] bg-card border-border text-text-sub w-full rounded-[4px] outline-none px-2 focus:border-green transition-colors"
             />
          </div>
          <button
            onClick={() => { setFrom(''); setTo('') }}
            title="Clear filters"
            className="w-[30px] h-[30px] flex items-center justify-center rounded-[4px] bg-card/50 border border-border text-text-dim hover:text-red hover:border-red/50 transition-colors shrink-0"
          >×</button>
        </div>
      </div>

      <div ref={listRef} className="flex-1 overflow-y-auto overflow-x-hidden" style={{ scrollbarWidth: 'thin' }}>
        {isPending && <p className="p-3 text-[13px] text-text-dim">Loading…</p>}
        {isError && <p className="p-3 text-[13px] text-red">Failed to load sessions</p>}
        {sessions.map(s => (
          <div key={s.tsid} data-tsid={s.tsid}>
            <SessionRow
              session={s}
              selected={s.tsid === selectedTsid}
              onClick={() => onSelect(s)}
            />
          </div>
        ))}
        {hasNextPage && (
          <div className="p-4 text-center border-t border-border/50">
            <button
              onClick={() => fetchNextPage()}
              disabled={isFetchingNextPage}
              className="text-text-dim hover:text-text text-[12px] font-medium transition-colors disabled:opacity-50"
            >
              {isFetchingNextPage ? 'Loading more…' : 'Load more'}
            </button>
          </div>
        )}
      </div>
      {data && (
        <div className="p-2 text-[11px] text-text-dim border-t border-border bg-surface">
          {sessions.length} / {total} sessions
        </div>
      )}
    </div>
  )
}
