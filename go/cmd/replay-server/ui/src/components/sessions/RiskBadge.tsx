import { cn } from '@/lib/utils'
import type { SessionInfo } from '@/types/session'

const styles: Record<SessionInfo['risk_level'], string> = {
  critical: 'bg-red-950 text-red-400 border-red-500/50',
  high:     'bg-orange-950 text-orange-400 border-orange-500/50',
  medium:   'bg-yellow-950 text-yellow-500 border-yellow-500/50',
  low:      'bg-blue-950 text-blue-400 border-blue-500/50',
  none:     'bg-zinc-900 text-zinc-500 border-zinc-700/50',
}

interface Props {
  level: SessionInfo['risk_level']
  score?: number
  className?: string
}

export function RiskBadge({ level, score, className }: Props) {
  return (
    <div className={cn(
      'px-2 py-0.5 rounded-[4px] border text-[10px] font-black uppercase tracking-widest transition-all',
      styles[level],
      className
    )}>
      {level} {score !== undefined && score > 0 ? `(${score})` : ''}
    </div>
  )
}
