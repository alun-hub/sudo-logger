import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchRetention, saveRetention } from '@/api/config'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Database, Clock } from 'lucide-react'

export function RetentionTab() {
  const qc = useQueryClient()
  const { data, isPending } = useQuery({ queryKey: ['retention'], queryFn: fetchRetention })
  const [cfg, setCfg] = useState<{ delete_after_days?: number; archive_cron?: string } | null>(null)
  const current = cfg ?? data ?? {}

  const save = useMutation({
    mutationFn: saveRetention,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['retention'] }); setCfg(null) },
  })

  if (isPending) return <div className="text-text-dim font-mono text-[13px]">Loading retention policy…</div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-border pb-2">
        <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
          <Database size={18} className="text-green" /> Data Retention
        </h2>
        <Button
          size="sm"
          onClick={() => save.mutate(current)}
          disabled={save.isPending || cfg === null}
          className="bg-green hover:bg-green/90 text-black font-semibold h-8 rounded-[5px]"
        >
          {save.isPending ? 'Saving…' : 'Save Policy'}
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div className="space-y-6">
          <div className="space-y-1.5 px-1">
            <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider flex items-center gap-2">
              <Clock size={14} /> Auto-deletion (Days)
            </label>
            <Input
              type="number"
              min={0}
              value={current.delete_after_days ?? 0}
              onChange={e => setCfg({ ...current, delete_after_days: Number(e.target.value) })}
              className="bg-card border-border text-text h-10 w-32 focus:border-green font-mono"
            />
            <p className="text-[11px] text-text-dim">Sessions older than this will be permanently deleted. Use 0 to disable.</p>
          </div>

          <div className="space-y-1.5 px-1">
            <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider">Archive Schedule (Cron)</label>
            <Input
              value={current.archive_cron ?? ''}
              onChange={e => setCfg({ ...current, archive_cron: e.target.value })}
              placeholder="0 2 * * *"
              className="bg-card border-border text-text h-10 focus:border-green font-mono"
            />
            <p className="text-[11px] text-text-dim">Schedule for background data compression and optimization.</p>
          </div>
        </div>

        <div className="bg-surface border border-border p-4 rounded-[5px] space-y-3 h-fit">
           <h3 className="text-[13px] font-semibold text-text uppercase tracking-wider">Storage Usage</h3>
           <div className="text-[12px] text-text-sub space-y-2">
             <div className="flex justify-between">
               <span>Session Index:</span>
               <span className="font-mono text-text">24.5 MB</span>
             </div>
             <div className="flex justify-between">
               <span>I/O Logs:</span>
               <span className="font-mono text-text">1.2 GB</span>
             </div>
             <div className="pt-2 border-t border-border flex justify-between font-bold">
               <span>Total:</span>
               <span className="font-mono text-green">1.22 GB</span>
             </div>
           </div>
        </div>
      </div>
    </div>
  )
}
