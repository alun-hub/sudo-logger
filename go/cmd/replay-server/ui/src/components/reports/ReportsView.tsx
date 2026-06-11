import { useQuery } from '@tanstack/react-query'
import { fetchReport, fetchAccessLog } from '@/api/reports'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { RiskBadge } from '@/components/sessions/RiskBadge'
import { fmtDate } from '@/lib/date'
import type { SessionInfo } from '@/types/session'

export function ReportsView() {
  const { data, isPending, isError } = useQuery({
    queryKey: ['report'],
    queryFn: fetchReport,
    refetchInterval: 60_000,
  })

  const { data: log } = useQuery({
    queryKey: ['access-log'],
    queryFn: fetchAccessLog,
  })

  if (isPending) return <div className="p-8 text-zinc-400">Loading…</div>
  if (isError)   return <div className="p-8 text-red-500">Failed to load report</div>

  return (
    <div className="p-6 overflow-y-auto h-[calc(100vh-3rem)] space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

        <Card>
          <CardHeader><CardTitle className="text-sm">Top Users by Risk</CardTitle></CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead className="text-right">Sessions</TableHead>
                  <TableHead className="text-right">Risk</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.top_users.map(u => (
                  <TableRow key={u.user}>
                    <TableCell className="font-mono text-xs">{u.user}</TableCell>
                    <TableCell className="text-right">{u.count}</TableCell>
                    <TableCell className="text-right">{u.risk_score.toFixed(1)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-sm">Top Hosts</CardTitle></CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Host</TableHead>
                  <TableHead className="text-right">Sessions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.top_hosts.map(h => (
                  <TableRow key={h.host}>
                    <TableCell className="font-mono text-xs">{h.host}</TableCell>
                    <TableCell className="text-right">{h.count}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-sm">Risky Commands</CardTitle></CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Command</TableHead>
                  <TableHead>Level</TableHead>
                  <TableHead className="text-right">Count</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.risky_commands.map((c, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono text-xs truncate max-w-[12rem]">{c.command}</TableCell>
                    <TableCell>
                      <RiskBadge level={c.level as SessionInfo['risk_level']} />
                    </TableCell>
                    <TableCell className="text-right">{c.count}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {log && (
        <Card>
          <CardHeader><CardTitle className="text-sm">Recent Access Log</CardTitle></CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Method</TableHead>
                  <TableHead>Path</TableHead>
                  <TableHead className="text-right">Status</TableHead>
                  <TableHead>IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {log.slice(0, 50).map((e, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono text-xs whitespace-nowrap">{fmtDate(e.time)}</TableCell>
                    <TableCell className="text-xs">{e.user || '—'}</TableCell>
                    <TableCell className="text-xs">{e.method}</TableCell>
                    <TableCell className="font-mono text-xs">{e.path}</TableCell>
                    <TableCell className={`text-right text-xs ${e.status >= 400 ? 'text-red-500' : ''}`}>
                      {e.status}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{e.remote_addr}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
