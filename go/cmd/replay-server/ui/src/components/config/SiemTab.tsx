import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchSiemConfig, saveSiemConfig, uploadSiemCert } from '@/api/config'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import type { SiemConfig } from '@/types/config'
import { Mail, ShieldAlert, FileKey, Globe, Zap } from 'lucide-react'
import { cn } from '@/lib/utils'

const TRANSPORTS = ['https', 'syslog'] as const
const FORMATS    = ['json', 'cef'] as const

export function SiemTab() {
  const qc = useQueryClient()
  const { data, isPending } = useQuery({ queryKey: ['siem-config'], queryFn: fetchSiemConfig })
  const [cfg, setCfg] = useState<SiemConfig | null>(null)
  const current: any = cfg ?? data ?? { enabled: false, transport: 'https', format: 'json' }

  const save = useMutation({
    mutationFn: saveSiemConfig,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['siem-config'] }); setCfg(null) },
  })

  const certUpload = useMutation({ mutationFn: uploadSiemCert })

  const set = (patch: any) => setCfg({ ...current, ...patch })

  if (isPending) return <div className="text-text-dim font-mono text-[13px]">Loading SIEM config…</div>

  return (
    <div className="space-y-8 max-w-5xl mx-auto animate-in fade-in duration-200">
      <div className="flex items-center justify-between border-b border-border pb-2">
        <div className="space-y-1">
          <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
            <Mail size={18} className="text-green" /> SIEM Forwarding
          </h2>
          <p className="text-[12px] text-text-dim">Forward audit logs and session I/O to a central security monitoring platform.</p>
        </div>
        <Button
          size="sm"
          onClick={() => save.mutate(current)}
          disabled={save.isPending || cfg === null}
          className="bg-green hover:bg-green/90 text-black font-bold h-8 rounded-[4px] px-6"
        >
          {save.isPending ? 'Saving…' : 'Save Config'}
        </Button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-8">
          <div className="flex items-center justify-between p-4 rounded-[5px] bg-card border border-border">
            <div className="space-y-0.5">
              <div className="text-[14px] font-medium text-text">Enable Forwarding</div>
              <div className="text-[12px] text-text-dim">Toggle real-time log streaming.</div>
            </div>
            <Switch checked={current.enabled} onCheckedChange={v => set({ enabled: v })} />
          </div>

          {current.enabled && (
            <div className="space-y-6 animate-in slide-in-from-top-2 duration-200">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5 px-1">
                  <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Transport</label>
                  <select
                    value={current.transport || 'https'}
                    onChange={e => set({ transport: e.target.value })}
                    className="block w-full rounded-[5px] border border-border bg-card px-3 h-10 text-[13px] outline-none focus:border-green"
                  >
                    {TRANSPORTS.map(t => <option key={t} value={t}>{t.toUpperCase()}</option>)}
                  </select>
                </div>
                <div className="space-y-1.5 px-1">
                  <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Format</label>
                  <select
                    value={current.format || 'json'}
                    onChange={e => set({ format: e.target.value })}
                    className="block w-full rounded-[5px] border border-border bg-card px-3 h-10 text-[13px] outline-none focus:border-green"
                  >
                    {FORMATS.map(f => <option key={f} value={f}>{f.toUpperCase()}</option>)}
                  </select>
                </div>
              </div>

              <div className="space-y-1.5 px-1">
                <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Endpoint URL / Host:Port</label>
                <div className="relative">
                   <Globe className="absolute left-3 top-2.5 text-text-dim" size={14} />
                   <Input
                    value={current.url ?? ''}
                    onChange={e => set({ url: e.target.value })}
                    placeholder={current.transport === 'syslog' ? 'logstash.example.com:514' : 'https://siem.example.com:8088/events'}
                    className="bg-card border-border text-text h-10 pl-9 focus:border-green font-mono text-[12px]"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-1.5 px-1">
                  <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Auth Token / Kafka Topic</label>
                  <div className="relative">
                    <Zap className="absolute left-3 top-2.5 text-text-dim" size={14} />
                    <Input
                      type="password"
                      value={current.token ?? ''}
                      onChange={e => set({ token: e.target.value })}
                      placeholder="x-x-x-x-x"
                      className="bg-card border-border text-text h-10 pl-9 focus:border-green font-mono text-[12px]"
                    />
                  </div>
                </div>
                <div className="space-y-1.5 px-1">
                  <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Replay Web App URL</label>
                  <Input
                    value={current.replay_url ?? ''}
                    onChange={e => set({ replay_url: e.target.value })}
                    placeholder="https://replay.example.com"
                    className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                  />
                </div>
              </div>

              <div className="space-y-4 pt-4 border-t border-border/50">
                <h3 className="text-[12px] font-bold text-text uppercase tracking-widest flex items-center gap-2">
                   <FileKey size={14} className="text-blue" /> mTLS & Certificates
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                   <CertField label="CA Certificate" onUpload={f => certUpload.mutate(f)} />
                   <CertField label="Client Certificate" onUpload={f => certUpload.mutate(f)} />
                   <CertField label="Client Private Key" onUpload={f => certUpload.mutate(f)} />
                </div>
              </div>
            </div>
          )}
        </div>

        <div className="space-y-6">
           <div className="p-4 rounded-[5px] bg-[#003d20]/20 border border-[#00e87a]/20 space-y-3">
             <div className="flex items-center gap-2 text-green font-bold text-[13px]">
               <ShieldAlert size={16} /> Data Sovereignty
             </div>
             <p className="text-[12px] text-text-sub leading-relaxed">
               All session events, including sensitive terminal I/O, will be forwarded in real-time.
               Ensure your SIEM endpoint is protected by high-entropy tokens and robust TLS.
             </p>
             <div className="text-[11px] text-text-dim bg-black/30 p-2 rounded italic">
                Logs are buffered locally on the log-server for up to 1 hour if the SIEM is unreachable.
             </div>
           </div>
        </div>
      </div>
    </div>
  )
}

function CertField({ label, onUpload }: { label: string, onUpload: (f: File) => void }) {
  return (
    <div className="space-y-1.5">
       <label className="text-[10px] font-bold text-text-dim uppercase tracking-wider">{label}</label>
       <div className="relative group">
          <input
            type="file"
            accept=".pem,.crt,.cer,.key"
            onChange={e => e.target.files?.[0] && onUpload(e.target.files[0])}
            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
          />
          <div className="h-9 border border-border border-dashed rounded-[4px] bg-card/50 flex items-center justify-center text-[11px] text-text-dim group-hover:border-green group-hover:text-text transition-colors">
             Select file...
          </div>
       </div>
    </div>
  )
}
