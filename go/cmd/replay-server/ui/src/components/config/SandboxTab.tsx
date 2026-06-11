import { useQuery } from '@tanstack/react-query'
import { fetchSandbox } from '@/api/config'
import { Switch } from '@/components/ui/switch'
import { Box, ShieldAlert, Lock, Zap } from 'lucide-react'
import { cn } from '@/lib/utils'

const FEATURES = [
  { id: 'deny-netlink', label: 'Deny Netlink', desc: 'Prevent network configuration changes.' },
  { id: 'deny-mount',   label: 'Deny Mount',   desc: 'Restrict filesystem mount operations.' },
  { id: 'deny-ptrace',  label: 'Deny PTrace',  desc: 'Prevent process debugging/inspection.' },
  { id: 'cap-net-admin', label: 'Drop CAP_NET_ADMIN', desc: 'Prevent network admin capabilities.' },
  { id: 'cap-sys-module', label: 'Drop CAP_SYS_MODULE', desc: 'Prevent kernel module loading.' },
  { id: 'cap-sys-rawio', label: 'Drop CAP_SYS_RAWIO', desc: 'Prevent raw I/O port access.' },
  { id: 'cap-sys-boot', label: 'Drop CAP_SYS_BOOT', desc: 'Prevent system reboot/shutdown.' },
  { id: 'systemd-ipc', label: 'Restrict Systemd IPC', desc: 'Isolate process from systemd bus.' },
]

export function SandboxTab() {
  const { data, isPending } = useQuery({ queryKey: ['sandbox'], queryFn: fetchSandbox })

  if (isPending) return <div className="text-text-dim font-mono text-[13px]">Loading sandbox config…</div>
  if (!data) return null

  return (
    <div className="space-y-8 max-w-5xl mx-auto animate-in fade-in duration-200">
      <div className="flex items-center justify-between border-b border-border pb-2">
        <div className="space-y-1">
          <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
            <Box size={18} className="text-green" /> Process Sandbox
          </h2>
          <p className="text-[12px] text-text-dim">Isolate risky commands in temporary, restricted containers.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-8">
           <div className="flex items-center justify-between p-4 rounded-[5px] bg-card border border-border">
              <div className="space-y-0.5">
                <div className="text-[14px] font-medium text-text">Agent Sandbox Enforcement</div>
                <div className="text-[12px] text-text-dim">When enabled, the agent redirects targeted commands into containers.</div>
              </div>
              <Switch checked={data.enabled} disabled />
            </div>

            <div className="space-y-4">
               <h3 className="text-[12px] font-bold text-text uppercase tracking-widest flex items-center gap-2">
                  <Lock size={14} className="text-blue" /> Default Security Features
               </h3>
               <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {FEATURES.map(f => (
                    <div key={f.id} className="p-3 rounded-[5px] bg-card/50 border border-border flex items-start gap-3">
                       <Switch checked={true} disabled className="mt-1" />
                       <div className="space-y-0.5">
                          <div className="text-[12px] font-bold text-text-sub">{f.label}</div>
                          <div className="text-[11px] text-text-dim leading-tight">{f.desc}</div>
                       </div>
                    </div>
                  ))}
               </div>
            </div>

            <div className="space-y-4">
               <h3 className="text-[12px] font-bold text-text uppercase tracking-widest flex items-center gap-2">
                  <Zap size={14} className="text-amber" /> Active Templates
               </h3>
               <div className="grid grid-cols-1 gap-2">
                  {(data?.templates || []).map(t => (
                    <div key={t.name} className="p-3 rounded-[5px] bg-surface border border-border flex items-center justify-between group">
                       <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded bg-blue/10 flex items-center justify-center text-blue font-bold font-mono text-[11px]">
                             {t.name[0].toUpperCase()}
                          </div>
                          <div className="font-mono text-[13px] text-text-sub">{t.name}</div>
                       </div>
                       <button className="text-[11px] text-text-dim hover:text-text opacity-0 group-hover:opacity-100 transition-opacity">View YAML</button>
                    </div>
                  ))}
               </div>
               <p className="text-[11px] text-text-dim italic">
                 Template management is currently handled via <code>sandbox.yaml</code>. Graphical editor is in development.
               </p>
            </div>
        </div>

        <div className="space-y-6">
           <div className="p-4 rounded-[5px] bg-[#003d20]/20 border border-[#00e87a]/20 space-y-3">
             <div className="flex items-center gap-2 text-green font-bold text-[13px]">
               <ShieldAlert size={16} /> Technology Stack
             </div>
             <div className="text-[12px] text-text-sub space-y-3 leading-relaxed">
               <p>The sandbox uses <strong>bubblewrap</strong> for unprivileged user namespaces and <strong>runc</strong> for container orchestration.</p>
               <p>Targeted commands are intercepted via the <code>sudo-logger-plugin</code> and transparently re-executed inside the sandbox.</p>
             </div>
           </div>
        </div>
      </div>
    </div>
  )
}
