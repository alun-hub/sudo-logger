import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchApprovals, approveRequest, denyRequest } from '@/api/approvals'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Button } from '@/components/ui/button'
import { fmtDate } from '@/lib/date'
import { ShieldCheck, Clock, CheckCircle, XCircle } from 'lucide-react'
import { cn } from '@/lib/utils'

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

  if (isPending) return <div className="p-8 text-text-dim font-mono text-[13px]">Loading requests…</div>
  if (isError)   return <div className="p-8 text-red font-mono text-[13px]">Failed to load approvals</div>

  const pending = (data ?? []).filter(r => r.status === 'pending')
  const history = (data ?? []).filter(r => r.status !== 'pending').slice(0, 20)

  return (
    <div className="flex flex-col h-[calc(100vh-[44px])] bg-bg text-text-sub overflow-y-auto p-6 space-y-12">
      {/* Pending Requests */}
      <section className="space-y-6">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
            <ShieldCheck size={18} className="text-green" /> Pending Approval Requests
            {pending.length > 0 && (
              <span className="ml-1 bg-red text-white text-[10px] rounded-full px-1.5 py-0.5 font-bold">
                {pending.length}
              </span>
            )}
          </h2>
        </div>

        <div className="rounded-[5px] border border-border bg-card overflow-hidden">
          <Table className="text-[13px]">
            <TableHeader className="bg-surface">
              <TableRow className="hover:bg-transparent border-border">
                <TableHead className="text-text-dim h-10 w-40">Time</TableHead>
                <TableHead className="text-text-dim h-10">Subject</TableHead>
                <TableHead className="text-text-dim h-10">Command</TableHead>
                <TableHead className="h-10 w-48"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pending.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="h-32 text-center text-text-dim italic">
                    No pending approval requests.
                  </TableCell>
                </TableRow>
              ) : (
                pending.map(r => (
                  <TableRow key={r.id} className="hover:bg-card-hover border-border h-12">
                    <TableCell className="text-text-dim font-mono text-[12px] whitespace-nowrap">
                      <div className="flex items-center gap-2">
                         <Clock size={12} /> {fmtDate(r.requested_at)}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono font-bold text-blue">{r.user}</span>
                      <span className="text-text-dim mx-1">@</span>
                      <span className="font-mono text-text-sub">{r.host}</span>
                    </TableCell>
                    <TableCell className="font-mono text-[12px] text-text truncate max-w-md">
                      {r.command}
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-2 px-2">
                        <Button
                          size="sm"
                          className="h-8 bg-green hover:bg-green/90 text-black font-bold text-[11px] px-3 rounded-[4px]"
                          onClick={() => approve.mutate(r.id)}
                          disabled={approve.isPending}
                        >APPROVE</Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-8 text-text-dim hover:text-red hover:bg-red/10 font-bold text-[11px] px-3 rounded-[4px]"
                          onClick={() => deny.mutate(r.id)}
                          disabled={deny.isPending}
                        >DENY</Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </section>

      {/* History */}
      {history.length > 0 && (
        <section className="space-y-6">
          <div className="flex items-center justify-between border-b border-border pb-2">
            <h2 className="text-[14px] font-semibold text-text-dim uppercase tracking-wider">Recent Activity</h2>
          </div>

          <div className="rounded-[5px] border border-border bg-card/50 overflow-hidden">
            <Table className="text-[12px]">
              <TableBody>
                {history.map(r => (
                  <TableRow key={r.id} className="hover:bg-card-hover border-border border-b last:border-0 h-10">
                    <TableCell className="text-text-dim font-mono w-40">{fmtDate(r.requested_at)}</TableCell>
                    <TableCell className="font-mono">
                      <span className="text-blue">{r.user}</span>
                      <span className="text-text-dim mx-1">@</span>
                      <span className="text-text-sub">{r.host}</span>
                    </TableCell>
                    <TableCell className="font-mono text-text-dim truncate max-w-sm">{r.command}</TableCell>
                    <TableCell className="text-right pr-4">
                       <div className="flex items-center justify-end gap-1.5 font-bold uppercase text-[10px]">
                         {r.status === 'approved' ? (
                           <>
                             <CheckCircle size={12} className="text-green" />
                             <span className="text-green">Approved</span>
                           </>
                         ) : (
                           <>
                             <XCircle size={12} className="text-red" />
                             <span className="text-red">Denied</span>
                           </>
                         )}
                         <span className="text-text-dim lowercase font-normal italic ml-2">by {r.approved_by || r.denied_by || 'system'}</span>
                       </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </section>
      )}
    </div>
  )
}
