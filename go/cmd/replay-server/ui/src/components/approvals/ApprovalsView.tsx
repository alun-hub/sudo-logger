import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchApprovals, approveRequest, denyRequest } from '@/api/approvals'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Button } from '@/components/ui/button'
import { fmtDate } from '@/lib/date'

export function ApprovalsView() {
  const qc = useQueryClient()
  const { data, isPending, isError } = useQuery({
    queryKey: ['approvals'],
    queryFn: fetchApprovals,
    refetchInterval: 10_000,
  })

  const approve = useMutation({
    mutationFn: approveRequest,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['approvals'] }),
  })
  const deny = useMutation({
    mutationFn: denyRequest,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['approvals'] }),
  })

  if (isPending) return <div className="p-8 text-zinc-400">Loading…</div>
  if (isError)   return <div className="p-8 text-red-500">Failed to load approvals</div>

  const pending = (data ?? []).filter(r => r.status === 'pending')

  return (
    <div className="p-6 overflow-y-auto h-[calc(100vh-3rem)]">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">
            Pending Approval Requests
            {pending.length > 0 && (
              <span className="ml-2 bg-red-500 text-white text-xs rounded-full px-1.5 py-0.5">
                {pending.length}
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {pending.length === 0 ? (
            <p className="text-zinc-400 text-sm">No pending requests</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Host</TableHead>
                  <TableHead>Command</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {pending.map(r => (
                  <TableRow key={r.id}>
                    <TableCell className="text-xs whitespace-nowrap">{fmtDate(r.requested_at)}</TableCell>
                    <TableCell className="font-mono text-xs">{r.user}</TableCell>
                    <TableCell className="font-mono text-xs">{r.host}</TableCell>
                    <TableCell className="font-mono text-xs truncate max-w-xs">{r.command}</TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          className="h-6 text-xs bg-emerald-600 hover:bg-emerald-700"
                          onClick={() => approve.mutate(r.id)}
                        >Approve</Button>
                        <Button
                          size="sm"
                          variant="destructive"
                          className="h-6 text-xs"
                          onClick={() => deny.mutate(r.id)}
                        >Deny</Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
