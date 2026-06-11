import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchSiemConfig, saveSiemConfig, uploadSiemCert } from '@/api/config'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import type { SiemConfig } from '@/types/config'
import { Mail, ShieldAlert } from 'lucide-react'

const TYPES = ['disabled', 'splunk', 'kafka', 'webhook'] as const

export function SiemTab() {
  const qc = useQueryClient()
  const { data, isPending } = useQuery({ queryKey: ['siem-config'], queryFn: fetchSiemConfig })
  const [cfg, setCfg] = useState<SiemConfig | null>(null)
  const current: SiemConfig = cfg ?? data ?? { type: 'disabled' }

  const save = useMutation({
    mutationFn: saveSiemConfig,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['siem-config'] }); setCfg(null) },
  })

  const certUpload = useMutation({ mutationFn: uploadSiemCert })

  const set = (patch: Partial<SiemConfig>) => setCfg({ ...current, ...patch })

  if (isPending) return <div className="text-text-dim font-mono text-[13px]">Loading SIEM config…</div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-border pb-2">
        <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
          <Mail size={18} className="text-green" /> SIEM Forwarding
        </h2>
        <Button
          size="sm"
          onClick={() => save.mutate(current)}
          disabled={save.isPending || cfg === null}
          className="bg-green hover:bg-green/90 text-black font-semibold h-8 rounded-[5px]"
        >
          {save.isPending ? 'Saving…' : 'Save Config'}
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        <div className="md:col-span-2 space-y-6">
          <div className="space-y-1.5 px-1">
            <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider">Integration Type</label>
            <select
              value={current.type}
              onChange={e => set({ type: e.target.value as SiemConfig['type'] })}
              className="block w-full rounded-[5px] border border-border bg-card px-3 h-10 text-[13px] outline-none focus:border-green"
            >
              {TYPES.map(t => <option key={t} value={t} className="bg-surface">{t.toUpperCase()}</option>)}
            </select>
          </div>

          {current.type !== 'disabled' && (
            <div className="space-y-4 animate-in slide-in-from-top-2 duration-200">
              <div className="space-y-1.5 px-1">
                <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider">Endpoint URL</label>
                <Input
                  value={current.url ?? ''}
                  onChange={e => set({ url: e.target.value })}
                  placeholder="https://siem.example.com:8088/services/collector"
                  className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                />
              </div>

              <div className="space-y-1.5 px-1">
                <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider">
                  {current.type === 'kafka' ? 'Topic Name' : 'Authentication Token'}
                </label>
                <Input
                  type={current.type === 'kafka' ? 'text' : 'password'}
                  value={current.type === 'kafka' ? (current.topic ?? '') : (current.token ?? '')}
                  onChange={e => current.type === 'kafka' ? set({ topic: e.target.value }) : set({ token: e.target.value })}
                  placeholder={current.type === 'kafka' ? 'sudo-audit-logs' : 'x-x-x-x-x'}
                  className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                />
              </div>

              <div className="space-y-1.5 px-1">
                <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider">Custom CA Certificate (PEM)</label>
                <div className="flex items-center gap-2">
                  <Input
                    type="file"
                    accept=".pem,.crt,.cer"
                    onChange={e => e.target.files?.[0] && certUpload.mutate(e.target.files[0])}
                    className="bg-card border-border text-text h-10 focus:border-green text-[12px] pt-[7px]"
                  />
                  {certUpload.isSuccess && <span className="text-green text-[12px] font-medium">✓ Uploaded</span>}
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="space-y-4">
           <div className="p-4 rounded-[5px] bg-[#003d20]/20 border border-[#00e87a]/20 space-y-2">
             <div className="flex items-center gap-2 text-green font-semibold text-[13px]">
               <ShieldAlert size={16} /> Data Security
             </div>
             <p className="text-[12px] text-text-sub leading-relaxed">
               All session events, including terminal I/O, will be forwarded to your SIEM in real-time.
               Ensure your endpoint is protected by TLS and authorized tokens.
             </p>
           </div>
        </div>
      </div>
    </div>
  )
}
