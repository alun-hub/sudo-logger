import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { SessionInfo } from '@/types/session'

const colors: Record<SessionInfo['risk_level'], string> = {
  critical: 'bg-red-600 text-white hover:bg-red-600',
  high:     'bg-orange-500 text-white hover:bg-orange-500',
  medium:   'bg-yellow-500 text-black hover:bg-yellow-500',
  low:      'bg-blue-500 text-white hover:bg-blue-500',
  none:     'bg-zinc-200 text-zinc-700 hover:bg-zinc-200',
}

export function RiskBadge({ level }: { level: SessionInfo['risk_level'] }) {
  return (
    <Badge className={cn('text-xs font-semibold uppercase', colors[level])}>
      {level}
    </Badge>
  )
}
