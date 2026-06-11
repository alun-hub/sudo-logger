import { useQuery } from '@tanstack/react-query'
import { fetchSandbox } from '@/api/config'
import { Switch } from '@/components/ui/switch'
import { Box, ShieldAlert } from 'lucide-react'

export function SandboxTab() {
  const { data, isPending } = useQuery({ queryKey: ['sandbox'], queryFn: fetchSandbox })

  if (isPending) return <div className="text-text-dim font-mono text-[13px]">Loading sandbox config…</div>
  if (!data) return null

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-border pb-2">
        <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
          <Box size={18} className="text-green" /> Process Sandbox
        </h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        <div className="space-y-6">
           <div className="flex items-center justify-between p-4 rounded-[5px] bg-card border border-border">
              <div className="space-y-0.5">
                <div className="text-[14px] font-medium text-text">Agent Sandbox Enforcement</div>
                <div className="text-[12px] text-text-dim">Run risky commands in isolated containers.</div>
              </div>
              <Switch checked={data.enabled} disabled />
            </div>

            <div className="p-4 bg-surface border border-border rounded-[5px] space-y-3">
               <h3 className="text-[12px] font-semibold text-text uppercase tracking-wider">Templates</h3>
               <div className="text-[13px] text-text-sub">
                 {data?.templates?.length ?? 0} active templates detected.
               </div>
               <p className="text-[11px] text-text-dim italic">
                 Template editing is currently managed via `sandbox.yaml` in the repository root.
                 A graphical editor is coming in a future release.
               </p>
            </div>
        </div>

        <div className="space-y-4">
           <div className="p-4 rounded-[5px] bg-[#003d20]/20 border border-[#00e87a]/20 space-y-2">
             <div className="flex items-center gap-2 text-green font-semibold text-[13px]">
               <ShieldAlert size={16} /> Security Note
             </div>
             <p className="text-[12px] text-text-sub leading-relaxed">
               Sandbox enforcement requires `bubblewrap` and `runc` to be installed on the client hosts.
               The agent will automatically redirect commands matching sandbox policies into the specified containers.
             </p>
           </div>
        </div>
      </div>
    </div>
  )
}
