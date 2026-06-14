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
  const isMissingPlugin = s.divergence_status === 'missing_plugin'
  const isEbpfPkexec    = s.source === 'ebpf-pkexec'
  const isDbusPolkit    = s.source === 'dbus-polkit'

  return (
    <button
      onClick={onClick}
      className={cn(
        'w-full text-left px-3.5 py-3 border-b border-border border-l-2 transition-colors flex flex-col',
        selected
          ? 'bg-card-active border-l-green'
          : 'bg-transparent border-l-transparent hover:bg-card-hover',
        !selected && s.in_progress    && 'border-l-[#4caf50]',
        !selected && s.incomplete     && 'border-l-red',
        !selected && s.network_outage && 'border-l-[#e67e00]',
        !selected && isEbpfPkexec     && 'border-l-[#8b6fff]',
        !selected && isDbusPolkit     && 'border-l-[#17a2b8]',
        !selected && isMissingPlugin  && 'border-l-red bg-red/5',
      )}
    >
      <div className="flex items-center justify-between gap-2 w-full">
        <div className="flex items-center gap-1.5 overflow-hidden">
          <span className={cn("text-[13.5px] font-bold font-mono truncate tracking-tight", selected ? "text-green" : "text-text")}>
            {s.user}@{s.host}
          </span>
          <span className={cn(
            "text-[9px] px-1.5 py-[0.5px] rounded-[3px] border font-black uppercase tracking-tighter shrink-0",
            s.runas === 'root'
              ? "text-text-dim border-border bg-card/50"
              : "text-blue border-blue/40 bg-blue/10"
          )}>
            → {isEbpfPkexec ? 'pkexec' : s.runas}
          </span>
        </div>
        <RiskBadge level={s.risk_level} score={s.risk_score} />
      </div>

      <div className="text-[12.5px] text-text-sub font-mono truncate mt-1.5 w-full text-left font-medium">
        {s.command}
      </div>

      <div className="text-[10.5px] text-text-dim font-mono truncate mt-0.5 w-full text-left">
        {isDbusPolkit ? `caller: ${s.caller_process}` : (s.cwd || s.tty || 'no tty')}
      </div>

      <div className="flex items-center justify-between w-full mt-2.5">
        <div className="flex items-center gap-1.5 text-[10px] text-text-dim/80 font-mono uppercase tracking-widest">
           {fmtDate(s.start_time)}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {s.in_progress && (
            <span className="text-[9px] text-[#4caf50] bg-[#4caf50]/10 border border-[#4caf50]/30 px-1.5 py-[0.5px] rounded-[3px] font-black uppercase tracking-widest flex items-center">
              <span className="mr-1 animate-pulse">●</span> live
            </span>
          )}
          {s.incomplete && (
            <span className="text-[9px] text-red bg-red/10 border border-red/30 px-1.5 py-[0.5px] rounded-[3px] font-black uppercase tracking-widest flex items-center">
              ⚠ incomplete
            </span>
          )}
          {s.network_outage && (
            <span className="text-[9px] text-[#e67e00] bg-[#e67e00]/10 border border-[#e67e00]/30 px-1.5 py-[0.5px] rounded-[3px] font-black uppercase tracking-widest">
              ⏱ outage
            </span>
          )}
          <span className={cn(
            "text-[10px] px-1.5 py-[0.5px] rounded-[3px] border font-mono font-bold",
            selected
              ? "text-green border-green-dim bg-green/5"
              : "text-blue border-border bg-card/30"
          )}>
            {fmtDuration(s.duration)}
          </span>
        </div>
      </div>
    </button>
  )
}
