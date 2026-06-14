import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchRetention, saveRetention } from '@/api/config'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import { Database, Clock, HardDrive } from 'lucide-react'

export function RetentionTab() {
  const qc = useQueryClient()
  const { data, isPending } = useQuery({ queryKey: ['retention'], queryFn: fetchRetention })
  const [cfg, setCfg] = useState<{ enabled?: boolean, days?: number } | null>(null)
  const current = cfg ?? data ?? { enabled: false, days: 90 }

  const save = useMutation({
    mutationFn: saveRetention,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['retention'] }); setCfg(null) },
  })

  if (isPending) return <div className="text-text-dim font-mono text-[13px]">Loading retention policy…</div>

  return (
    <div className="space-y-8 max-w-4xl mx-auto animate-in fade-in duration-200">
      <div className="flex items-center justify-between border-b border-border pb-2">
        <div className="space-y-1">
          <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
            <Database size={18} className="text-green" /> Data Retention
          </h2>
          <p className="text-[12px] text-text-dim">Manage how long session data and terminal logs are stored on the server.</p>
        </div>
        <Button
          size="sm"
          onClick={() => save.mutate(current)}
          disabled={save.isPending || cfg === null}
          className="bg-green hover:bg-green/90 text-black font-bold h-8 rounded-[4px] px-6"
        >
          {save.isPending ? 'Saving…' : 'Save Policy'}
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div className="space-y-6">
          <div className="flex items-center justify-between p-4 rounded-[5px] bg-card border border-border">
            <div className="space-y-0.5">
              <div className="text-[14px] font-medium text-text">Auto-Cleanup</div>
              <div className="text-[12px] text-text-dim">Automatically delete old sessions.</div>
            </div>
            <Switch checked={current.enabled} onCheckedChange={v => setCfg({ ...current, enabled: v })} />
          </div>

          <div className="space-y-1.5 px-1">
            <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider flex items-center gap-2">
              <Clock size={14} /> Delete after (Days)
            </label>
            <Input
              type="number"
              min={1}
              disabled={!current.enabled}
              value={current.days ?? 90}
              onChange={e => setCfg({ ...current, days: Number(e.target.value) })}
              className="bg-card border-border text-text h-10 w-32 focus:border-green font-mono"
            />
            <p className="text-[11px] text-text-dim">Sessions older than this will be permanently purged.</p>
          </div>
        </div>

        <div className="bg-surface border border-border p-4 rounded-[5px] space-y-4 h-fit">
           <h3 className="text-[13px] font-bold text-text uppercase tracking-widest flex items-center gap-2">
              <HardDrive size={14} className="text-blue" /> Storage Summary
           </h3>
           <div className="text-[12px] text-text-sub space-y-3">
             <div className="flex justify-between items-baseline border-b border-border/50 pb-1">
               <span>Session Metadata:</span>
               <span className="font-mono text-text">24.5 MB</span>
             </div>
             <div className="flex justify-between items-baseline border-b border-border/50 pb-1">
               <span>Terminal I/O Logs:</span>
               <span className="font-mono text-text">1.2 GB</span>
             </div>
             <div className="flex justify-between items-baseline font-bold pt-1">
               <span className="text-text">Total Usage:</span>
               <span className="font-mono text-green text-lg">1.22 GB</span>
             </div>
           </div>
           <div className="bg-blue/5 border border-blue/20 p-3 rounded text-[11px] text-text-dim leading-relaxed italic">
              Retention policies are evaluated daily. Purged data cannot be recovered.
           </div>
        </div>
      </div>
    </div>
  )
}
