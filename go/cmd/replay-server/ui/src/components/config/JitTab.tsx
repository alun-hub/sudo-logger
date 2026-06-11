import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchJitPolicy, saveJitPolicy, fetchApprovalConfig, saveApprovalConfig } from '@/api/config'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Switch } from '@/components/ui/switch'
import type { JitPolicy, ApprovalConfig } from '@/types/config'
import { ShieldCheck, BellRing } from 'lucide-react'

export function JitTab() {
  const qc = useQueryClient()

  const { data: jit, isPending: p1 }      = useQuery({ queryKey: ['jit-policy'], queryFn: fetchJitPolicy })
  const { data: approval, isPending: p2 } = useQuery({ queryKey: ['approval-config'], queryFn: fetchApprovalConfig })

  const [jitDraft, setJitDraft]           = useState<JitPolicy | null>(null)
  const [approvalDraft, setApprovalDraft] = useState<ApprovalConfig | null>(null)

  const saveJit = useMutation({
    mutationFn: saveJitPolicy,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['jit-policy'] }); setJitDraft(null) },
  })
  const saveApproval = useMutation({
    mutationFn: saveApprovalConfig,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['approval-config'] }); setApprovalDraft(null) },
  })

  if (p1 || p2) return <div className="text-text-dim font-mono text-[13px]">Loading configuration…</div>

  const j = jitDraft ?? jit ?? { enabled: false, ttl_seconds: 3600 }
  const a = approvalDraft ?? approval ?? {
    enabled: false,
    ttl_seconds: 900,
    roles_that_can_approve: [],
    default_window: '30m'
  }

  return (
    <div className="space-y-12">
      {/* JIT Policy Section */}
      <section className="space-y-6">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
            <ShieldCheck size={18} className="text-green" /> JIT Policy
          </h2>
          <Button
            size="sm"
            onClick={() => saveJit.mutate(j)}
            disabled={saveJit.isPending || jitDraft === null}
            className="bg-green hover:bg-green/90 text-black font-semibold h-8 rounded-[5px]"
          >
            {saveJit.isPending ? 'Saving…' : 'Save Changes'}
          </Button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
          <div className="space-y-6">
            <div className="flex items-center justify-between p-4 rounded-[5px] bg-card border border-border">
              <div className="space-y-0.5">
                <div className="text-[14px] font-medium text-text">Just-In-Time Access</div>
                <div className="text-[12px] text-text-dim">Require approval for high-risk sessions.</div>
              </div>
              <Switch checked={j.enabled} onCheckedChange={v => setJitDraft({ ...j, enabled: v })} />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Default Window</label>
                <Input
                  value={a.default_window ?? '30m'}
                  onChange={e => setApprovalDraft({ ...a, default_window: e.target.value })}
                  placeholder="30m"
                  className="bg-card border-border text-text h-10 focus:border-green font-mono"
                />
              </div>
              <div className="space-y-1.5">
                <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Pending TTL</label>
                <Input
                  value={j.ttl_seconds}
                  type="number"
                  onChange={e => setJitDraft({ ...j, ttl_seconds: Number(e.target.value) })}
                  className="bg-card border-border text-text h-10 focus:border-green font-mono"
                />
              </div>
            </div>
          </div>

          <div className="bg-surface border border-border p-4 rounded-[5px] space-y-3">
             <h3 className="text-[13px] font-semibold text-text uppercase tracking-wider">How it works</h3>
             <ul className="text-[12px] text-text-sub space-y-2 list-disc pl-4 leading-relaxed">
               <li>When a user requests a session matching a JIT rule, it is blocked.</li>
               <li>A request is sent to the configured webhooks.</li>
               <li>Approvers can approve via CLI, API, or Replay UI.</li>
               <li>Once approved, the user can run the command for the duration of the TTL.</li>
             </ul>
          </div>
        </div>
      </section>

      {/* Approval Config Section */}
      <section className="space-y-6">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
            <BellRing size={18} className="text-blue" /> Notification & Webhooks
          </h2>
          <Button
            size="sm"
            onClick={() => saveApproval.mutate(a)}
            disabled={saveApproval.isPending || approvalDraft === null}
            className="bg-green hover:bg-green/90 text-black font-semibold h-8 rounded-[5px]"
          >
            {saveApproval.isPending ? 'Saving…' : 'Save Changes'}
          </Button>
        </div>

        <div className="space-y-8">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
             <div className="space-y-6">
                <div className="space-y-1.5 px-1">
                  <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Webhook URL</label>
                  <Input
                    value={a.webhook_url ?? ''}
                    onChange={e => setApprovalDraft({ ...a, webhook_url: e.target.value })}
                    placeholder="https://chat.example.com/hooks/..."
                    className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                  />
                </div>

                <div className="space-y-1.5 px-1">
                  <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Webhook Secret</label>
                  <Input
                    type="password"
                    value={a.webhook_secret ?? ''}
                    onChange={e => setApprovalDraft({ ...a, webhook_secret: e.target.value })}
                    className="bg-card border-border text-text h-10 focus:border-green font-mono"
                  />
                </div>
             </div>

             <div className="space-y-6">
                <div className="space-y-1.5 px-1">
                  <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Bot Username</label>
                  <Input
                    value={a.bot_username ?? ''}
                    onChange={e => setApprovalDraft({ ...a, bot_username: e.target.value })}
                    placeholder="sudo-logger-bot"
                    className="bg-card border-border text-text h-10 focus:border-green"
                  />
                </div>
                <div className="space-y-1.5 px-1">
                  <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Request Channel</label>
                  <Input
                    value={a.request_channel ?? ''}
                    onChange={e => setApprovalDraft({ ...a, request_channel: e.target.value })}
                    placeholder="sudo-audit"
                    className="bg-card border-border text-text h-10 focus:border-green"
                  />
                </div>
             </div>
          </div>

          <div className="space-y-4 pt-4 border-t border-border/50">
             <div className="space-y-1.5 px-1">
                <label className="text-[11px] font-bold text-text-sub uppercase tracking-wider">Replay Web App URL</label>
                <Input
                  value={a.replay_web_url ?? ''}
                  onChange={e => setApprovalDraft({ ...a, replay_web_url: e.target.value })}
                  placeholder="https://replay.example.com"
                  className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                />
                <p className="text-[11px] text-text-dim">Base URL included in notifications for quick playback access.</p>
             </div>

             <div className="flex items-center justify-between p-4 rounded-[5px] bg-card border border-border">
                <div className="space-y-0.5">
                  <div className="text-[14px] font-medium text-text">Mention User</div>
                  <div className="text-[12px] text-text-dim">Tag the requesting user in the notification.</div>
                </div>
                <Switch
                  checked={!!a.mention_user}
                  onCheckedChange={v => setApprovalDraft({ ...a, mention_user: v })}
                />
              </div>
          </div>
        </div>
      </section>
    </div>
  )
}
