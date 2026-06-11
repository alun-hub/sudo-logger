import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchJitPolicy, saveJitPolicy, fetchApprovalConfig, saveApprovalConfig } from '@/api/config'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import type { JitPolicy, ApprovalConfig } from '@/types/config'

export function JitTab() {
  const qc = useQueryClient()

  const { data: jit }      = useQuery({ queryKey: ['jit-policy'], queryFn: fetchJitPolicy })
  const { data: approval } = useQuery({ queryKey: ['approval-config'], queryFn: fetchApprovalConfig })

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

  const j = jitDraft ?? jit ?? { enabled: false, ttl_seconds: 3600 }
  const a = approvalDraft ?? approval ?? { enabled: false, ttl_seconds: 900, roles_that_can_approve: [] }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex justify-between">
            JIT Policy
            <Button size="sm" onClick={() => saveJit.mutate(j)} disabled={saveJit.isPending || jitDraft === null}>
              {saveJit.isPending ? 'Saving…' : 'Save'}
            </Button>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-2">
            <Switch checked={j.enabled} onCheckedChange={v => setJitDraft({ ...j, enabled: v })} />
            <Label>Enable JIT approval</Label>
          </div>
          <div className="space-y-1">
            <Label>TTL (seconds)</Label>
            <Input type="number" value={j.ttl_seconds} className="w-32"
              onChange={e => setJitDraft({ ...j, ttl_seconds: Number(e.target.value) })} />
          </div>
          {j.webhook_url !== undefined && (
            <div className="space-y-1">
              <Label>Webhook URL</Label>
              <Input value={j.webhook_url ?? ''} onChange={e => setJitDraft({ ...j, webhook_url: e.target.value })} />
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm flex justify-between">
            Approval Config
            <Button size="sm" onClick={() => saveApproval.mutate(a)} disabled={saveApproval.isPending || approvalDraft === null}>
              {saveApproval.isPending ? 'Saving…' : 'Save'}
            </Button>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-2">
            <Switch checked={a.enabled} onCheckedChange={v => setApprovalDraft({ ...a, enabled: v })} />
            <Label>Enable approval workflow</Label>
          </div>
          <div className="space-y-1">
            <Label>Approval TTL (seconds)</Label>
            <Input type="number" value={a.ttl_seconds} className="w-32"
              onChange={e => setApprovalDraft({ ...a, ttl_seconds: Number(e.target.value) })} />
          </div>
          <div className="space-y-1">
            <Label>Webhook URL (Mattermost/Slack)</Label>
            <Input value={a.webhook_url ?? ''} onChange={e => setApprovalDraft({ ...a, webhook_url: e.target.value })} />
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
