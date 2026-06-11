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
        'w-full text-left px-3 py-2 text-sm border-b border-zinc-100 dark:border-zinc-800',
        'hover:bg-zinc-50 dark:hover:bg-zinc-800/50 transition-colors',
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
