import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchApprovals, approveRequest, denyRequest } from '@/api/approvals'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Button } from '@/components/ui/button'
import { fmtDate } from '@/lib/date'
import { ShieldCheck, Clock, CheckCircle, XCircle } from 'lucide-react'

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

  const parseDate = (d: any) => {
    if (typeof d === 'number') return d
    if (!d) return 0
    return Math.floor(new Date(d).getTime() / 1000)
  }

  const pending = (data ?? []).filter(r => r.status === 'pending')
  const history = (data ?? []).filter(r => r.status !== 'pending').slice(0, 20)

  return (
    <div className="flex flex-col h-[calc(100vh-48px)] bg-bg text-text-sub overflow-y-auto scrollbar-thin p-8 space-y-12">
      {/* Pending Requests */}
      <section className="space-y-6 max-w-7xl mx-auto w-full">
        <div className="flex items-center justify-between border-b border-border pb-3">
          <h2 className="text-[16px] font-bold text-text flex items-center gap-2 uppercase tracking-widest">
            <ShieldCheck size={20} className="text-green" /> Pending Approval Requests
            {pending.length > 0 && (
              <span className="ml-2 bg-red text-white text-[11px] rounded-full px-2 py-0.5 font-black animate-pulse">
                {pending.length}
              </span>
            )}
          </h2>
        </div>

        <div className="rounded-[8px] border border-border bg-card shadow-2xl overflow-hidden">
          <Table className="text-[13px]">
            <TableHeader className="bg-surface/80 backdrop-blur-sm">
              <TableRow className="hover:bg-transparent border-border h-11">
                <TableHead className="text-text-dim font-bold uppercase tracking-tighter text-[11px] w-44">Time</TableHead>
                <TableHead className="text-text-dim font-bold uppercase tracking-tighter text-[11px] w-48">Subject</TableHead>
                <TableHead className="text-text-dim font-bold uppercase tracking-tighter text-[11px]">Command / Reason</TableHead>
                <TableHead className="h-11 w-56"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {pending.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="h-40 text-center text-text-dim italic bg-surface/30">
                    <div className="flex flex-col items-center gap-2">
                       <CheckCircle size={32} className="opacity-20" />
                       No pending approval requests.
                    </div>
                  </TableCell>
                </TableRow>
              ) : (
                pending.map(r => (
                  <TableRow key={r.id} className="hover:bg-card-hover border-border h-14 transition-colors">
                    <TableCell className="text-text-dim font-mono text-[12px] whitespace-nowrap">
                      <div className="flex items-center gap-2">
                         <Clock size={12} className="text-amber" /> {fmtDate(parseDate((r as any).requested_at || (r as any).submitted_at))}
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-col">
                        <span className="font-mono font-bold text-blue text-[14px]">{r.user}</span>
                        <span className="text-[10px] text-text-dim uppercase font-mono">on {r.host}</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-3">
                       <div className="space-y-1">
                          <code className="bg-surface px-1.5 py-0.5 rounded border border-border/40 text-[12px] text-text">{r.command}</code>
                          <div className="text-[12px] text-text-dim italic flex items-center gap-1.5 px-1">
                             <span className="font-bold text-[10px] uppercase text-amber/60">Reason:</span> {(r as any).justification || 'No reason provided.'}
                          </div>
                       </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex justify-end gap-2 px-2">
                        <Button
                          size="sm"
                          className="h-8 bg-green hover:bg-green/90 text-black font-black text-[11px] px-4 rounded-[4px] shadow-sm"
                          onClick={() => approve.mutate(r.id)}
                          disabled={approve.isPending}
                        >APPROVE</Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-8 text-text-dim hover:text-red hover:bg-red/10 font-bold text-[11px] px-4 rounded-[4px]"
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
        <section className="space-y-6 max-w-7xl mx-auto w-full opacity-80 hover:opacity-100 transition-opacity">
          <div className="flex items-center justify-between border-b border-border pb-3">
            <h2 className="text-[14px] font-bold text-text-dim uppercase tracking-[0.2em]">Recent Activity</h2>
          </div>

          <div className="rounded-[8px] border border-border bg-card/40 overflow-hidden">
            <Table className="text-[12px]">
              <TableBody>
                {history.map(r => (
                  <TableRow key={r.id} className="hover:bg-card-hover border-border border-b last:border-0 h-12">
                    <TableCell className="text-text-dim font-mono w-44">{fmtDate(parseDate((r as any).requested_at || (r as any).submitted_at))}</TableCell>
                    <TableCell className="font-mono w-48">
                      <span className="text-blue font-bold">{r.user}</span>
                      <span className="text-text-dim mx-1 font-normal opacity-50">@</span>
                      <span className="text-text-sub">{r.host}</span>
                    </TableCell>
                    <TableCell className="font-mono text-text-dim truncate max-w-md">
                       <span className="opacity-60">{r.command}</span>
                    </TableCell>
                    <TableCell className="text-right pr-6">
                       <div className="flex items-center justify-end gap-2 font-black uppercase text-[10px] tracking-widest">
                         {r.status === 'approved' ? (
                           <>
                             <CheckCircle size={14} className="text-green" />
                             <span className="text-green">Approved</span>
                           </>
                         ) : (
                           <>
                             <XCircle size={14} className="text-red" />
                             <span className="text-red">Denied</span>
                           </>
                         )}
                         <span className="text-text-dim lowercase font-normal italic ml-3 opacity-60">by {r.approved_by || r.denied_by || 'system'}</span>
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
