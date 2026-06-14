import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchApprovalConfig, saveApprovalConfig } from '@/api/config'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import type { ApprovalConfig } from '@/types/config'
import { ShieldCheck, BellRing } from 'lucide-react'

const EMPTY: ApprovalConfig = {
  enabled: false,
  default_window: '30m',
  pending_ttl: '15m',
  exempt: [],
  notifications: {
    webhook_url: '',
    webhook_secret: '',
    mention_user: false,
    request_channel: '',
    replay_web_app_url: '',
  },
}

export function JitTab() {
  const qc = useQueryClient()
  const { data, isPending } = useQuery({ queryKey: ['approval-config'], queryFn: fetchApprovalConfig })
  const [draft, setDraft] = useState<ApprovalConfig | null>(null)

  const save = useMutation({
    mutationFn: saveApprovalConfig,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['approval-config'] }); setDraft(null) },
  })

  if (isPending) return <div className="text-text-dim font-mono text-[13px]">Loading configuration…</div>

  const cfg: ApprovalConfig = draft ?? data ?? EMPTY

  const set = (patch: Partial<ApprovalConfig>) => setDraft({ ...cfg, ...patch })
  const setNotif = (patch: Partial<ApprovalConfig['notifications']>) =>
    set({ notifications: { ...cfg.notifications, ...patch } })

  return (
    <div className="space-y-12">
      {/* JIT / Approval Policy */}
      <section className="space-y-6">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
            <ShieldCheck size={18} className="text-green" /> JIT / Approval Policy
          </h2>
          <Button
            size="sm"
            onClick={() => save.mutate(cfg)}
            disabled={save.isPending || draft === null}
            className="bg-green hover:bg-green/90 text-black font-semibold h-8 rounded-[5px]"
          >
            {save.isPending ? 'Saving…' : 'Save Changes'}
          </Button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="space-y-6">
            <div className="flex items-center justify-between p-4 rounded-[5px] bg-card border border-border">
              <div className="space-y-0.5">
                <div className="text-[14px] font-medium text-text">Enable JIT Workflow Engine</div>
                <div className="text-[12px] text-text-dim">Globally enables the JIT infrastructure, webhooks, and the approvals queue.</div>
              </div>
              <Switch checked={cfg.enabled} onCheckedChange={v => set({ enabled: v })} />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Default Window</label>
                <Input
                  value={cfg.default_window}
                  onChange={e => set({ default_window: e.target.value })}
                  placeholder="30m"
                  className="bg-card border-border text-text h-10 focus:border-green font-mono"
                />
                <p className="text-[11px] text-text-dim">How long an approval grants access (e.g. 30m, 2h).</p>
              </div>
              <div className="space-y-1.5">
                <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Pending TTL</label>
                <Input
                  value={cfg.pending_ttl}
                  onChange={e => set({ pending_ttl: e.target.value })}
                  placeholder="15m"
                  className="bg-card border-border text-text h-10 focus:border-green font-mono"
                />
                <p className="text-[11px] text-text-dim">How long a pending request stays open.</p>
              </div>
            </div>
          </div>

          <div className="bg-surface border border-border p-4 rounded-[5px] space-y-3">
             <h3 className="text-[13px] font-semibold text-text uppercase tracking-wider">How it works</h3>
             <ul className="text-[12px] text-text-sub space-y-2 list-disc pl-4 leading-relaxed">
               <li>When a user requests a session matching a JIT rule, it is blocked.</li>
               <li>A request is sent to the configured webhook.</li>
               <li>Approvers can approve or deny in the Approvals tab.</li>
               <li>Once approved, the user can run the command for the default window duration.</li>
             </ul>
          </div>
        </div>
      </section>

      {/* Notification / Webhook Config */}
      <section className="space-y-6">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
            <BellRing size={18} className="text-blue" /> Notifications & Webhooks
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
           <div className="space-y-6">
              <div className="space-y-1.5 px-1">
                <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Webhook URL</label>
                <Input
                  value={cfg.notifications.webhook_url}
                  onChange={e => setNotif({ webhook_url: e.target.value })}
                  placeholder="https://chat.example.com/hooks/..."
                  className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                />
              </div>

              <div className="space-y-1.5 px-1">
                <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Webhook Secret</label>
                <Input
                  type="password"
                  value={cfg.notifications.webhook_secret}
                  onChange={e => setNotif({ webhook_secret: e.target.value })}
                  placeholder="••••••••"
                  className="bg-card border-border text-text h-10 focus:border-green font-mono"
                />
                <p className="text-[11px] text-text-dim">Used to sign Slack interactive callbacks (approve/deny buttons).</p>
              </div>
           </div>

           <div className="space-y-6">
              <div className="space-y-1.5 px-1">
                <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Request Channel</label>
                <Input
                  value={cfg.notifications.request_channel}
                  onChange={e => setNotif({ request_channel: e.target.value })}
                  placeholder="#sudo-audit"
                  className="bg-card border-border text-text h-10 focus:border-green"
                />
              </div>
              <div className="space-y-1.5 px-1">
                <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Replay Web App URL</label>
                <Input
                  value={cfg.notifications.replay_web_app_url}
                  onChange={e => setNotif({ replay_web_app_url: e.target.value })}
                  placeholder="https://replay.example.com"
                  className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                />
                <p className="text-[11px] text-text-dim">Base URL for approve/deny deep-links in notifications.</p>
              </div>
           </div>
        </div>

        <div className="flex items-center justify-between p-4 rounded-[5px] bg-card border border-border">
           <div className="space-y-0.5">
             <div className="text-[14px] font-medium text-text">Mention User</div>
             <div className="text-[12px] text-text-dim">Tag the requesting user in Slack notifications.</div>
           </div>
           <Switch
             checked={cfg.notifications.mention_user}
             onCheckedChange={v => setNotif({ mention_user: v })}
           />
        </div>
      </section>
    </div>
  )
}
