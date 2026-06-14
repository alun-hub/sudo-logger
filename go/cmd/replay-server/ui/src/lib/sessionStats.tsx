import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'

interface SessionStats {
  shown: number
  total: number
  setStats: (shown: number, total: number) => void
}

const Ctx = createContext<SessionStats>({ shown: 0, total: 0, setStats: () => {} })

export function SessionStatsProvider({ children }: { children: ReactNode }) {
  const [shown, setShown] = useState(0)
  const [total, setTotal] = useState(0)
  const setStats = useCallback((s: number, t: number) => { setShown(s); setTotal(t) }, [])
  return <Ctx.Provider value={{ shown, total, setStats }}>{children}</Ctx.Provider>
}

export function useSessionStats() {
  return useContext(Ctx)
}
