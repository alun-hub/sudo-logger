import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { fetchReport } from '@/api/reports'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { fmtDate, fmtDuration } from '@/lib/date'
import { cn } from '@/lib/utils'
import { X } from 'lucide-react'

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

  if (isPending) return <div className="p-8 text-[#4a5068] font-mono text-[13px]">Loading…</div>
  if (isError)   return <div className="p-8 text-red font-mono text-[13px]">Failed to load report</div>

  const s = data.summary

  return (
    <div className="flex flex-col h-[calc(100vh-[44px])] bg-bg text-text-sub overflow-hidden">
      <Tabs defaultValue="summary" className="flex-1 flex flex-col">
        <div className="px-4 border-b border-border bg-surface shrink-0 flex items-center justify-between">
          <TabsList className="h-[44px] bg-transparent p-0 gap-1">
            <TabsTrigger
              value="summary"
              className="h-full rounded-none border-b-2 border-transparent data-[state=active]:border-green data-[state=active]:bg-transparent data-[state=active]:text-green px-4 text-[13px] font-medium transition-all"
            >
              Summary
            </TabsTrigger>
            <TabsTrigger
              value="anomalies"
              className="h-full rounded-none border-b-2 border-transparent data-[state=active]:border-green data-[state=active]:bg-transparent data-[state=active]:text-green px-4 text-[13px] font-medium transition-all"
            >
              Anomalies
            </TabsTrigger>
          </TabsList>

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
          <TabsContent value="summary" className="m-0 p-6 space-y-8 animate-in fade-in duration-200">
            {/* Period info */}
            {s.period_from > 0 && (
              <div className="text-[12px] text-text-dim font-mono mb-4">
                Showing {s.total_sessions} sessions from {fmtDate(s.period_from)} to {fmtDate(s.period_to)}
              </div>
            )}

            {/* Stats Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
              <StatCard label="Sessions" value={s.total_sessions} />
              <StatCard label="Users" value={s.unique_users} />
              <StatCard label="Hosts" value={s.unique_hosts} />
              <StatCard label="Incomplete" value={s.incomplete_sessions} color={s.incomplete_sessions > 0 ? 'text-red' : ''} />
              <StatCard label="Long (>2h)" value={s.long_sessions} color={s.long_sessions > 0 ? 'text-amber' : ''} />
              <StatCard label="High Risk" value={s.high_risk_sessions} color={s.high_risk_sessions > 0 ? 'text-amber' : ''} />
              <StatCard label="Critical" value={s.critical_sessions} color={s.critical_sessions > 0 ? 'text-red' : ''} />
            </div>

            {/* Per User Table */}
            <div className="space-y-3">
              <h2 className="text-[15px] font-semibold text-text">Per User</h2>
              <div className="rounded-[5px] border border-border bg-card overflow-hidden">
                <Table className="text-[13px]">
                  <TableHeader className="bg-surface">
                    <TableRow className="hover:bg-transparent border-border">
                      <TableHead className="text-text-dim font-medium h-9">User</TableHead>
                      <TableHead className="text-text-dim font-medium h-9 text-right">Sessions</TableHead>
                      <TableHead className="text-text-dim font-medium h-9 text-right">Avg Duration</TableHead>
                      <TableHead className="text-text-dim font-medium h-9">Top Commands</TableHead>
                      <TableHead className="text-text-dim font-medium h-9 text-right">Hosts</TableHead>
                      <TableHead className="text-text-dim font-medium h-9 text-right">Incomplete</TableHead>
                      <TableHead className="text-text-dim font-medium h-9 text-right">Long (&gt;2h)</TableHead>
                      <TableHead className="text-text-dim font-medium h-9 text-right">High Risk</TableHead>
                      <TableHead className="text-text-dim font-medium h-9 text-right">Critical</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.per_user.map(u => (
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
          </TabsContent>

          <TabsContent value="anomalies" className="m-0 p-6 animate-in fade-in duration-200">
             <div className="space-y-3">
              <h2 className="text-[15px] font-semibold text-text">Anomalies</h2>
              <div className="rounded-[5px] border border-border bg-card overflow-hidden">
                <Table className="text-[13px]">
                  <TableHeader className="bg-surface">
                    <TableRow className="hover:bg-transparent border-border">
                      <TableHead className="text-text-dim font-medium h-9">Type</TableHead>
                      <TableHead className="text-text-dim font-medium h-9">Risk</TableHead>
                      <TableHead className="text-text-dim font-medium h-9">User</TableHead>
                      <TableHead className="text-text-dim font-medium h-9">Host</TableHead>
                      <TableHead className="text-text-dim font-medium h-9">Command</TableHead>
                      <TableHead className="text-text-dim font-medium h-9">Time</TableHead>
                      <TableHead className="text-text-dim font-medium h-9">Duration</TableHead>
                      <TableHead className="text-text-dim font-medium h-9">Detail</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.anomalies.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={8} className="h-24 text-center text-text-dim italic">
                          No anomalies found in this period.
                        </TableCell>
                      </TableRow>
                    ) : (
                      data.anomalies.map((a, i) => (
                        <TableRow key={i} className="hover:bg-card-hover border-border h-10">
                          <TableCell className="text-text font-medium">{a.kind}</TableCell>
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
          </TabsContent>
        </div>
      </Tabs>
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
