import { useQueryClient } from '@tanstack/react-query'
import type { MeResponse } from '@/types/config'

export function useCan() {
  const qc = useQueryClient()
  const me = qc.getQueryData<MeResponse>(['me'])
  return (perm: string): boolean => {
    if (!me) return true  // optimistic while loading
    if (me.role === 'admin') return true
    return (me.permissions ?? []).includes(perm)
  }
}
