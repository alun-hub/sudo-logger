import { useState, useMemo } from 'react'
import { useNavigate, Routes, Route, NavLink, Navigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { fetchReport } from '@/api/reports'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { fmtDate, fmtDuration } from '@/lib/date'
import { cn } from '@/lib/utils'
import { X, BarChart2, AlertCircle } from 'lucide-react'

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
    <div className="flex flex-col h-[calc(100vh-[44px])] bg-bg text-text-sub overflow-hidden">
      <div className="px-4 border-b border-border bg-surface shrink-0 flex items-center justify-between">
        <nav className="h-[44px] flex items-center gap-1">
          <SubTab to="/reports/summary"   label="Summary"   icon={<BarChart2 size={14} />} />
          <SubTab to="/reports/anomalies" label="Anomalies" icon={<AlertCircle size={14} />} />
        </nav>

        <div className="flex items-center gap-2 text-[12px]">
          <label className="text-text-dim">From</label>
          <input
            type="date"
            value={from}
            onChange={e => setFrom(e.target.value)}
            className="bg-card border border-border rounded-[5px] px-1.5 py-0.5 outline-none focus:border-green text-text-sub h-[24px]"
          />
          <label className="text-text-dim">To</label>
          <input
            type="date"
            value={to}
            onChange={e => setTo(e.target.value)}
            className="bg-card border border-border rounded-[5px] px-1.5 py-0.5 outline-none focus:border-green text-text-sub h-[24px]"
          />
          {(from || to) && (
            <button
              onClick={() => { setFrom(''); setTo('') }}
              className="text-text-dim hover:text-red transition-colors"
            >
              <X size={14} />
            </button>
          )}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto">
        <Routes>
          <Route path="summary"   element={<SummaryTab data={data} />} />
          <Route path="anomalies" element={<AnomaliesTab data={data} />} />
          <Route path=""          element={<Navigate to="summary" replace />} />
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
        "h-full flex items-center gap-2 px-4 text-[13px] font-medium transition-all border-b-2",
        isActive
          ? "border-green text-green"
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
    <div className="p-6 space-y-8 animate-in fade-in duration-200">
      {s.period_from > 0 && (
        <div className="text-[12px] text-text-dim font-mono">
          Showing {s.total_sessions} sessions from {fmtDate(s.period_from)} to {fmtDate(s.period_to)}
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
        <StatCard label="Sessions" value={s.total_sessions} />
        <StatCard label="Users" value={s.unique_users} />
        <StatCard label="Hosts" value={s.unique_hosts} />
        <StatCard label="Incomplete" value={s.incomplete_sessions} color={s.incomplete_sessions > 0 ? 'text-red' : ''} />
        <StatCard label="Long (>2h)" value={s.long_sessions} color={s.long_sessions > 0 ? 'text-amber' : ''} />
        <StatCard label="High Risk" value={s.high_risk_sessions} color={s.high_risk_sessions > 0 ? 'text-amber' : ''} />
        <StatCard label="Critical" value={s.critical_sessions} color={s.critical_sessions > 0 ? 'text-red' : ''} />
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-[15px] font-semibold text-text">Per User</h2>
          <input
            placeholder="Search user…"
            value={q}
            onChange={e => setQ(e.target.value)}
            className="h-8 bg-card border border-border rounded-[5px] px-3 text-[12px] outline-none focus:border-green w-48"
          />
        </div>
        <div className="rounded-[5px] border border-border bg-card overflow-hidden">
          <Table className="text-[13px]">
            <TableHeader className="bg-surface">
              <TableRow className="hover:bg-transparent border-border">
                <SortHeader label="User" col="user" current={sortCol} dir={sortDir} onSort={toggleSort} />
                <SortHeader label="Sessions" col="sessions" current={sortCol} dir={sortDir} onSort={toggleSort} textAlign="right" />
                <SortHeader label="Avg Duration" col="avg_duration" current={sortCol} dir={sortDir} onSort={toggleSort} textAlign="right" />
                <TableHead className="text-text-dim font-medium h-9">Top Commands</TableHead>
                <SortHeader label="Hosts" col="hosts" current={sortCol} dir={sortDir} onSort={toggleSort} textAlign="right" />
                <SortHeader label="Incomplete" col="incomplete" current={sortCol} dir={sortDir} onSort={toggleSort} textAlign="right" />
                <SortHeader label="Long (>2h)" col="long_sessions" current={sortCol} dir={sortDir} onSort={toggleSort} textAlign="right" />
                <SortHeader label="High Risk" col="high_risk" current={sortCol} dir={sortDir} onSort={toggleSort} textAlign="right" />
                <SortHeader label="Critical" col="critical" current={sortCol} dir={sortDir} onSort={toggleSort} textAlign="right" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((u: any) => (
                <TableRow key={u.user} className="hover:bg-card-hover border-border h-10">
                  <TableCell className="font-mono font-semibold text-blue">{u.user}</TableCell>
                  <TableCell className="text-right font-mono">{u.sessions}</TableCell>
                  <TableCell className="text-right font-mono text-text-dim">{fmtDuration(u.avg_duration)}</TableCell>
                  <TableCell className="text-text-dim font-mono max-w-[200px] truncate">
                    {u.top_commands.slice(0, 3).join(', ')}
                  </TableCell>
                  <TableCell className="text-right font-mono text-text-dim">{u.hosts}</TableCell>
                  <TableCell className={cn("text-right font-mono", u.incomplete > 0 ? "text-red" : "text-text-dim")}>
                    {u.incomplete || '—'}
                  </TableCell>
                  <TableCell className={cn("text-right font-mono", u.long_sessions > 0 ? "text-amber" : "text-text-dim")}>
                    {u.long_sessions || '—'}
                  </TableCell>
                  <TableCell className={cn("text-right font-mono", u.high_risk > 0 ? "text-amber" : "text-text-dim")}>
                    {u.high_risk || '—'}
                  </TableCell>
                  <TableCell className={cn("text-right font-mono", u.critical > 0 ? "text-red font-bold" : "text-text-dim")}>
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

  return (
    <div className="p-6 animate-in fade-in duration-200">
       <div className="space-y-4">
        <h2 className="text-[15px] font-semibold text-text">Anomalies</h2>
        <div className="rounded-[5px] border border-border bg-card overflow-hidden">
          <Table className="text-[13px]">
            <TableHeader className="bg-surface">
              <TableRow className="hover:bg-transparent border-border">
                <SortHeader label="Type" col="kind" current={sortCol} dir={sortDir} onSort={toggleSort} />
                <SortHeader label="Risk" col="risk_score" current={sortCol} dir={sortDir} onSort={toggleSort} />
                <SortHeader label="User" col="user" current={sortCol} dir={sortDir} onSort={toggleSort} />
                <SortHeader label="Host" col="host" current={sortCol} dir={sortDir} onSort={toggleSort} />
                <TableHead className="text-text-dim font-medium h-9">Command</TableHead>
                <SortHeader label="Time" col="start_time" current={sortCol} dir={sortDir} onSort={toggleSort} />
                <SortHeader label="Duration" col="duration" current={sortCol} dir={sortDir} onSort={toggleSort} />
                <TableHead className="text-text-dim font-medium h-9">Detail</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {sorted.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="h-24 text-center text-text-dim italic">
                    No anomalies found in this period.
                  </TableCell>
                </TableRow>
              ) : (
                sorted.map((a: any, i: number) => (
                  <TableRow
                    key={i}
                    className="hover:bg-card-hover border-border h-10 cursor-pointer group"
                    onClick={() => navigate(`/?tsid=${a.tsid}`)}
                  >
                    <TableCell className="text-text font-medium group-hover:text-green transition-colors">{a.kind}</TableCell>
                    <TableCell>
                      <span className={cn(
                        "px-1.5 py-0.5 rounded-[3px] text-[10px] font-bold uppercase",
                        a.risk_score && a.risk_score >= 75 ? "bg-red text-white" : "bg-amber text-black"
                      )}>
                        {a.risk_score || 'HIGH'}
                      </span>
                    </TableCell>
                    <TableCell className="text-blue font-mono">{a.user}</TableCell>
                    <TableCell className="text-text-dim font-mono">{a.host}</TableCell>
                    <TableCell className="text-text-sub font-mono truncate max-w-[150px]">{a.command}</TableCell>
                    <TableCell className="text-text-dim whitespace-nowrap">{fmtDate(a.start_time)}</TableCell>
                    <TableCell className="text-text-dim font-mono">{fmtDuration(a.duration)}</TableCell>
                    <TableCell className="text-text-dim italic truncate max-w-[200px]">{a.detail}</TableCell>
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
    <div className="bg-card border border-border p-3 rounded-[5px] shadow-sm">
      <div className="text-[11px] text-text-dim uppercase tracking-wider font-medium mb-1">{label}</div>
      <div className={cn("text-xl font-mono font-bold tabular-nums", color || "text-text")}>{value}</div>
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
        "text-text-dim font-medium h-9 cursor-pointer hover:text-text transition-colors",
        active && "text-green font-bold",
        textAlign === 'right' && "text-right"
      )}
      onClick={() => onSort(col)}
    >
      {label} {active && (dir === 'asc' ? '↑' : '↓')}
    </TableHead>
  )
}
