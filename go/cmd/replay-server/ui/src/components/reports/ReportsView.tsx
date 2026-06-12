import { useState, useMemo } from 'react'
import { useNavigate, Routes, Route, NavLink, Navigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { fetchReport } from '@/api/reports'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { fmtDate, fmtDuration } from '@/lib/date'
import { cn } from '@/lib/utils'
import {
  X, BarChart2, AlertCircle, ShieldAlert, Clock, Zap,
  ShieldX, AlertTriangle, Box, PlayCircle
} from 'lucide-react'

export function ReportsView() {
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')

  const fromTs = from ? Math.floor(new Date(from).getTime() / 1000) : 0
  const toTs   = to   ? Math.floor(new Date(to).getTime() / 1000) : 0

  const { data, isPending, isError } = useQuery({
    queryKey: ['report', fromTs, toTs],
    queryFn: () => fetchReport({ from: fromTs, to: toTs }),
    refetchInterval: 60_000,
  })

  if (isPending) return <div className="p-8 text-text-dim font-mono text-[13px]">Loading report…</div>
  if (isError)   return <div className="p-8 text-red font-mono text-[13px]">Failed to load report</div>

  return (
    <div className="flex flex-col h-[calc(100vh-48px)] bg-bg text-text-sub overflow-hidden">
      <div className="px-4 border-b border-border bg-surface shrink-0 flex items-center justify-between shadow-sm z-10">
        <nav className="h-[44px] flex items-center gap-1">
          <SubTab to="/reports/summary"   label="Summary"   icon={<BarChart2 size={14} />} />
          <SubTab to="/reports/anomalies" label="Anomalies" icon={<AlertCircle size={14} />} />
        </nav>

        <div className="flex items-center gap-4 text-[12px]">
          <div className="flex items-center gap-2">
            <label className="text-text-dim font-bold uppercase tracking-tighter">From</label>
            <input
              type="date"
              value={from}
              onChange={e => setFrom(e.target.value)}
              className="bg-card border border-border rounded-[4px] px-2 py-0.5 outline-none focus:border-green text-text-sub h-[26px] font-mono"
            />
          </div>
          <div className="flex items-center gap-2">
            <label className="text-text-dim font-bold uppercase tracking-tighter">To</label>
            <input
              type="date"
              value={to}
              onChange={e => setTo(e.target.value)}
              className="bg-card border border-border rounded-[4px] px-2 py-0.5 outline-none focus:border-green text-text-sub h-[26px] font-mono"
            />
          </div>
          {(from || to) && (
            <button
              onClick={() => { setFrom(''); setTo('') }}
              className="text-text-dim hover:text-red transition-colors p-1"
            >
              <X size={16} />
            </button>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto scrollbar-thin">
        <Routes>
          <Route path="summary"   element={<SummaryTab data={data} />} />
          <Route path="anomalies" element={<AnomaliesTab data={data} />} />
          <Route path=""          element={<Navigate to="/reports/summary" replace />} />
        </Routes>
      </div>
    </div>
  )
}

function SubTab({ to, label, icon }: { to: string, label: string, icon: React.ReactNode }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) => cn(
        "h-full flex items-center gap-2 px-6 text-[13px] font-bold transition-all border-b-2 uppercase tracking-wide",
        isActive
          ? "border-green text-green bg-green/5"
          : "border-transparent text-text-dim hover:text-text-sub hover:bg-card-hover"
      )}
    >
      {icon} {label}
    </NavLink>
  )
}

function SummaryTab({ data }: { data: any }) {
  const [q, setQ] = useState('')
  const [sortCol, setSortCol] = useState('sessions')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  const s = data.summary

  const filtered = useMemo(() => {
    let list = data.per_user.filter((u: any) => u.user.toLowerCase().includes(q.toLowerCase()))
    list.sort((a: any, b: any) => {
      const vA = a[sortCol]
      const vB = b[sortCol]
      if (vA < vB) return sortDir === 'asc' ? -1 : 1
      if (vA > vB) return sortDir === 'asc' ? 1 : -1
      return 0
    })
    return list
  }, [data.per_user, q, sortCol, sortDir])

  const toggleSort = (col: string) => {
    if (sortCol === col) setSortDir(sortDir === 'asc' ? 'desc' : 'asc')
    else { setSortCol(col); setSortDir('desc') }
  }

  return (
    <div className="p-8 space-y-10 animate-in fade-in duration-300 max-w-[1600px] mx-auto">
      {s.period_from > 0 && (
        <div className="text-[12px] text-text-dim font-mono bg-card/30 p-2 rounded border border-border/50 inline-block">
          📅 Period: <span className="text-text-sub">{fmtDate(s.period_from)}</span> → <span className="text-text-sub">{fmtDate(s.period_to)}</span>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
        <StatCard label="Total Sessions" value={s.total_sessions} />
        <StatCard label="Unique Users" value={s.unique_users} />
        <StatCard label="Active Hosts" value={s.unique_hosts} />
        <StatCard label="Incomplete" value={s.incomplete_sessions} color={s.incomplete_sessions > 0 ? 'text-red' : ''} />
        <StatCard label="Long (>2h)" value={s.long_sessions} color={s.long_sessions > 0 ? 'text-amber' : ''} />
        <StatCard label="High Risk" value={s.high_risk_sessions} color={s.high_risk_sessions > 0 ? 'text-amber' : ''} />
        <StatCard label="Critical" value={s.critical_sessions} color={s.critical_sessions > 0 ? 'text-red' : ''} />
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <h2 className="text-[16px] font-bold text-text uppercase tracking-widest">User Activity Audit</h2>
          <div className="relative">
             <input
               placeholder="Filter by user..."
               value={q}
               onChange={e => setQ(e.target.value)}
               className="h-9 bg-card border border-border rounded-[6px] px-4 text-[13px] outline-none focus:border-green w-64 transition-all"
             />
          </div>
        </div>
        <div className="rounded-[8px] border border-border bg-card shadow-lg overflow-hidden">
          <Table className="text-[13px]">
            <TableHeader className="bg-surface/80 backdrop-blur-sm">
              <TableRow className="hover:bg-transparent border-border">
                <SortHeader label="User" col="user" current={sortCol} dir={sortDir} onSort={toggleSort} />
                <SortHeader label="Sessions" col="sessions" current={sortCol} dir={sortDir} onSort={toggleSort} textAlign="right" />
                <SortHeader label="Avg Duration" col="avg_duration" current={sortCol} dir={sortDir} onSort={toggleSort} textAlign="right" />
                <TableHead className="text-text-dim font-bold h-11 uppercase tracking-tighter text-[11px]">Top Commands</TableHead>
                <SortHeader label="Hosts" col="hosts" current={sortCol} dir={sortDir} onSort={toggleSort} textAlign="right" />
                <SortHeader label="Incomplete" col="incomplete" current={sortCol} dir={sortDir} onSort={toggleSort} textAlign="right" />
                <SortHeader label="Long" col="long_sessions" current={sortCol} dir={sortDir} onSort={toggleSort} textAlign="right" />
                <SortHeader label="High Risk" col="high_risk" current={sortCol} dir={sortDir} onSort={toggleSort} textAlign="right" />
                <SortHeader label="Critical" col="critical" current={sortCol} dir={sortDir} onSort={toggleSort} textAlign="right" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((u: any) => (
                <TableRow key={u.user} className="hover:bg-card-hover border-border h-12 transition-colors">
                  <TableCell className="font-mono font-bold text-blue text-[14px]">{u.user}</TableCell>
                  <TableCell className="text-right font-mono font-bold">{u.sessions}</TableCell>
                  <TableCell className="text-right font-mono text-text-dim">{fmtDuration(u.avg_duration)}</TableCell>
                  <TableCell className="text-text-dim font-mono max-w-[300px] truncate">
                    {u.top_commands.slice(0, 4).map((c: string) => (
                       <span key={c} className="bg-surface px-1.5 py-0.5 rounded border border-border/50 mr-1 text-[11px]">{c}</span>
                    ))}
                  </TableCell>
                  <TableCell className="text-right font-mono text-text-dim">{u.hosts}</TableCell>
                  <TableCell className={cn("text-right font-mono", u.incomplete > 0 ? "text-red font-bold" : "text-text-dim")}>
                    {u.incomplete || '—'}
                  </TableCell>
                  <TableCell className={cn("text-right font-mono", u.long_sessions > 0 ? "text-amber font-bold" : "text-text-dim")}>
                    {u.long_sessions || '—'}
                  </TableCell>
                  <TableCell className={cn("text-right font-mono", u.high_risk > 0 ? "text-amber font-bold" : "text-text-dim")}>
                    {u.high_risk || '—'}
                  </TableCell>
                  <TableCell className={cn("text-right font-mono", u.critical > 0 ? "text-red font-black" : "text-text-dim")}>
                    {u.critical || '—'}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      </div>
    </div>
  )
}

function AnomaliesTab({ data }: { data: any }) {
  const navigate = useNavigate()
  const [sortCol, setSortCol] = useState('start_time')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  const sorted = useMemo(() => {
    let list = [...data.anomalies]
    list.sort((a: any, b: any) => {
      const vA = a[sortCol]
      const vB = b[sortCol]
      if (vA < vB) return sortDir === 'asc' ? -1 : 1
      if (vA > vB) return sortDir === 'asc' ? 1 : -1
      return 0
    })
    return list
  }, [data.anomalies, sortCol, sortDir])

  const toggleSort = (col: string) => {
    if (sortCol === col) setSortDir(sortDir === 'asc' ? 'desc' : 'asc')
    else { setSortCol(col); setSortDir('desc') }
  }

  const getAnomalyIcon = (kind: string) => {
    switch (kind) {
      case 'root_shell': return <ShieldAlert size={14} className="text-red" />
      case 'after_hours': return <Clock size={14} className="text-amber" />
      case 'high_risk': return <Zap size={14} className="text-amber" />
      case 'policy_violation': return <ShieldX size={14} className="text-red" />
      case 'incomplete': return <AlertTriangle size={14} className="text-orange" />
      case 'sandbox_violation': return <Box size={14} className="text-red" />
      default: return <AlertCircle size={14} className="text-text-dim" />
    }
  }

  return (
    <div className="p-8 animate-in fade-in duration-300 max-w-[1600px] mx-auto">
       <div className="space-y-6">
        <div className="flex items-center justify-between border-b border-border pb-2">
           <h2 className="text-[16px] font-bold text-text uppercase tracking-widest">Security Anomalies Log</h2>
           <span className="text-[11px] text-text-dim font-mono bg-card px-3 py-1 rounded-full border border-border">
              {sorted.length} events detected
           </span>
        </div>

        <div className="rounded-[8px] border border-border bg-card shadow-2xl overflow-hidden">
          <Table className="text-[13px]">
            <TableHeader className="bg-surface/80 backdrop-blur-sm">
              <TableRow className="hover:bg-transparent border-border h-11">
                <SortHeader label="Type" col="kind" current={sortCol} dir={sortDir} onSort={toggleSort} />
                <SortHeader label="Risk" col="risk_score" current={sortCol} dir={sortDir} onSort={toggleSort} />
                <SortHeader label="User" col="user" current={sortCol} dir={sortDir} onSort={toggleSort} />
                <SortHeader label="Host" col="host" current={sortCol} dir={sortDir} onSort={toggleSort} />
                <TableHead className="text-text-dim font-bold uppercase tracking-tighter text-[11px]">Command</TableHead>
                <SortHeader label="Time" col="start_time" current={sortCol} dir={sortDir} onSort={toggleSort} />
                <SortHeader label="Duration" col="duration" current={sortCol} dir={sortDir} onSort={toggleSort} />
                <TableHead className="text-text-dim font-bold uppercase tracking-tighter text-[11px]">Detail</TableHead>
                <TableHead className="w-12 h-11"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sorted.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={9} className="h-32 text-center text-text-dim italic">
                    No security anomalies found in this period. Everything looks nominal.
                  </TableCell>
                </TableRow>
              ) : (
                sorted.map((a: any, i: number) => (
                  <TableRow
                    key={i}
                    className="hover:bg-card-hover border-border h-12 cursor-pointer group transition-colors"
                    onClick={() => navigate(`/?tsid=${a.tsid}`)}
                  >
                    <TableCell className="font-bold group-hover:text-green transition-colors">
                       <div className="flex items-center gap-2">
                          {getAnomalyIcon(a.kind)}
                          <span className="capitalize">{a.kind.replace('_', ' ')}</span>
                       </div>
                    </TableCell>
                    <TableCell>
                      <span className={cn(
                        "px-2 py-0.5 rounded-[4px] border text-[10px] font-black uppercase tracking-widest",
                        a.risk_score >= 75 ? "bg-red-950/40 text-red-400 border-red-500/50" :
                        a.risk_score >= 40 ? "bg-orange-950/40 text-orange-400 border-orange-500/50" :
                        "bg-yellow-950/40 text-yellow-500 border-yellow-500/50"
                      )}>
                        {a.risk_score || 'HIGH'}
                      </span>
                    </TableCell>
                    <TableCell className="text-blue font-mono font-bold text-[14px]">{a.user}</TableCell>
                    <TableCell className="text-text-sub font-mono">{a.host}</TableCell>
                    <TableCell className="text-text-sub font-mono truncate max-w-[200px]">
                       <code className="bg-surface/50 px-1.5 py-0.5 rounded border border-border/40">{a.command}</code>
                    </TableCell>
                    <TableCell className="text-text-dim whitespace-nowrap font-mono text-[12px]">{fmtDate(a.start_time)}</TableCell>
                    <TableCell className="text-text-dim font-mono text-[12px]">{fmtDuration(a.duration)}</TableCell>
                    <TableCell className="text-text-dim italic truncate max-w-[250px] text-[12px] opacity-80">{a.detail}</TableCell>
                    <TableCell>
                       <div className="flex justify-end pr-2">
                          <PlayCircle size={18} className="text-text-dim group-hover:text-green transition-colors" />
                       </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </div>
    </div>
  )
}

function StatCard({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="bg-card border border-border p-4 rounded-[8px] shadow-lg hover:border-border-mid transition-colors group">
      <div className="text-[10px] text-text-dim uppercase tracking-[0.15em] font-black mb-2 group-hover:text-text-sub">{label}</div>
      <div className={cn("text-2xl font-mono font-bold tabular-nums tracking-tighter", color || "text-text")}>{value}</div>
    </div>
  )
}

function SortHeader({ label, col, current, dir, onSort, textAlign }: {
  label: string,
  col: string,
  current: string,
  dir: 'asc' | 'desc',
  onSort: (col: string) => void,
  textAlign?: 'left' | 'right'
}) {
  const active = current === col
  return (
    <TableHead
      className={cn(
        "text-text-dim font-bold h-11 cursor-pointer hover:text-text transition-colors uppercase tracking-tighter text-[11px]",
        active && "text-green font-black",
        textAlign === 'right' && "text-right"
      )}
      onClick={() => onSort(col)}
    >
      <div className={cn("flex items-center gap-1", textAlign === 'right' && "justify-end")}>
         {label} {active && (dir === 'asc' ? '↑' : '↓')}
      </div>
    </TableHead>
  )
}
