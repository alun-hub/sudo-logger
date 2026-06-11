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
        'w-full text-left px-3.5 py-3 border-b border-[#1e2230] border-l-2 transition-colors flex flex-col',
        selected
          ? 'bg-[#1a2035] border-l-[#00e87a]'
          : 'bg-transparent border-l-transparent hover:bg-[#1c1f2e]'
      )}
    >
      <div className="flex items-center justify-between gap-2 w-full">
        <div className="flex items-center gap-1.5 overflow-hidden">
          <span className={cn("textsm font-semibold font-mono truncate", selected ? "text-[#00e87a]" : "text-[#d4daf0]")}>
            {s.user}@{s.host}
          </span>
          <span className={cn(
            "text-[10px] px-1.5 py-[1px] rounded border font-medium shrink-0",
            s.runas === 'root'
              ? "text-[#8890a8] border-[#1e2230] bg-[#161921]"
              : "text-[#4da8ff] border-[#4da8ff]/30 bg-[#4da8ff]/10"
          )}>
            -- {s.runas}
          </span>
        </div>
        <RiskBadge level={s.risk_level} />
      </div>

      <div className="text-[13px] text-[#8890a8] font-mono truncate mt-1 w-full text-left">
        {s.command}
      </div>

      {s.cwd && (
        <div className="text-[11px] text-[#4a5068] font-mono truncate mt-0.5 w-full text-left">
          {s.cwd}
        </div>
      )}

      <div className="flex items-center justify-between w-full mt-1.5">
        <span className="text-[11px] text-[#8890a8] font-sans">
          {fmtDate(s.start_time)}
        </span>

        <div className="flex items-center gap-1.5 shrink-0">
          {s.in_progress && (
            <span className="text-[11px] text-[#4caf50] bg-[#4caf50]/10 border border-[#4caf50]/30 px-1.5 py-[1px] rounded font-sans flex items-center">
              <span className="mr-1 animate-pulse">●</span> live
            </span>
          )}
          <span className={cn(
            "text-[11px] px-1.5 py-[1px] rounded border font-sans",
            selected
              ? "text-[#00e87a] border-[#003d20] bg-transparent"
              : "text-[#4da8ff] border-[#1e2230] bg-[#161921]"
          )}>
            {fmtDuration(s.duration)}
          </span>
        </div>
      </div>
    </button>
  )
}
