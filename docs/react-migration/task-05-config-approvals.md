# Task 05: Config Panel + Approvals View

## Context
Two remaining SPA tabs:

**Config** — Settings panel with sub-tabs: SIEM integration, Authentication
(OIDC/proxy/local), Users & Roles, Retention, Sandbox, JIT/Approval config.

**Approvals** — Pending sudo approval requests (only active when the
approval proxy is enabled on the server). Shows a table with approve/deny actions.

## Working directory
`/home/alun/sudo-logger/go/cmd/replay-server/ui`

## Prerequisites
Tasks 01–04 complete.

## Install shadcn/ui components

```bash
npx shadcn@latest add dialog alert-dialog switch label form
```

---

## Config Panel

### src/components/config/ConfigPanel.tsx

```tsx
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { SiemTab }       from './SiemTab'
import { AuthTab }       from './AuthTab'
import { UsersRolesTab } from './UsersRolesTab'
import { RetentionTab }  from './RetentionTab'
import { SandboxTab }    from './SandboxTab'
import { JitTab }        from './JitTab'

export function ConfigPanel() {
  return (
    <div className="p-6 overflow-y-auto h-[calc(100vh-3rem)]">
      <Tabs defaultValue="siem">
        <TabsList className="mb-4 flex-wrap h-auto gap-1">
          <TabsTrigger value="siem">SIEM</TabsTrigger>
          <TabsTrigger value="auth">Auth</TabsTrigger>
          <TabsTrigger value="users">Users & Roles</TabsTrigger>
          <TabsTrigger value="retention">Retention</TabsTrigger>
          <TabsTrigger value="sandbox">Sandbox</TabsTrigger>
          <TabsTrigger value="jit">JIT / Approvals</TabsTrigger>
        </TabsList>
        <TabsContent value="siem"><SiemTab /></TabsContent>
        <TabsContent value="auth"><AuthTab /></TabsContent>
        <TabsContent value="users"><UsersRolesTab /></TabsContent>
        <TabsContent value="retention"><RetentionTab /></TabsContent>
        <TabsContent value="sandbox"><SandboxTab /></TabsContent>
        <TabsContent value="jit"><JitTab /></TabsContent>
      </Tabs>
    </div>
  )
}
```

### src/components/config/SiemTab.tsx

```tsx
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchSiemConfig, saveSiemConfig, uploadSiemCert } from '@/api/config'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import type { SiemConfig } from '@/types/config'

const TYPES = ['disabled', 'splunk', 'kafka', 'webhook'] as const

export function SiemTab() {
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['siem-config'], queryFn: fetchSiemConfig })
  const [cfg, setCfg] = useState<SiemConfig | null>(null)
  const current: SiemConfig = cfg ?? data ?? { type: 'disabled' }

  const save = useMutation({
    mutationFn: saveSiemConfig,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['siem-config'] }); setCfg(null) },
  })

  const certUpload = useMutation({ mutationFn: uploadSiemCert })

  const set = (patch: Partial<SiemConfig>) => setCfg({ ...current, ...patch })

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex justify-between">
          SIEM Integration
          <Button size="sm" onClick={() => save.mutate(current)} disabled={save.isPending || cfg === null}>
            {save.isPending ? 'Saving…' : 'Save'}
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1">
          <Label>Type</Label>
          <select
            value={current.type}
            onChange={e => set({ type: e.target.value as SiemConfig['type'] })}
            className="block w-full rounded-md border border-zinc-200 dark:border-zinc-700 bg-transparent px-3 py-1.5 text-sm"
          >
            {TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        {current.type !== 'disabled' && (
          <>
            <div className="space-y-1">
              <Label>URL</Label>
              <Input value={current.url ?? ''} onChange={e => set({ url: e.target.value })} />
            </div>
            <div className="space-y-1">
              <Label>{current.type === 'kafka' ? 'Topic' : 'Token / Secret'}</Label>
              <Input
                type="password"
                value={current.type === 'kafka' ? (current.topic ?? '') : (current.token ?? '')}
                onChange={e => current.type === 'kafka' ? set({ topic: e.target.value }) : set({ token: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label>TLS Certificate (PEM)</Label>
              <Input
                type="file"
                accept=".pem,.crt,.cer"
                onChange={e => e.target.files?.[0] && certUpload.mutate(e.target.files[0])}
              />
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}
```

### src/components/config/AuthTab.tsx

```tsx
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchAuthConfig, saveAuthConfig } from '@/api/config'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import type { AuthConfig } from '@/types/config'

const MODES = ['local', 'oidc', 'proxy'] as const

export function AuthTab() {
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['auth-config'], queryFn: fetchAuthConfig })
  const [cfg, setCfg] = useState<AuthConfig | null>(null)
  const current: AuthConfig = cfg ?? data ?? { mode: 'local' }

  const save = useMutation({
    mutationFn: saveAuthConfig,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['auth-config'] }); setCfg(null) },
  })

  const set = (patch: Partial<AuthConfig>) => setCfg({ ...current, ...patch })

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex justify-between">
          Authentication
          <Button size="sm" onClick={() => save.mutate(current)} disabled={save.isPending || cfg === null}>
            {save.isPending ? 'Saving…' : 'Save'}
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1">
          <Label>Mode</Label>
          <select
            value={current.mode}
            onChange={e => set({ mode: e.target.value as AuthConfig['mode'] })}
            className="block w-full rounded-md border border-zinc-200 dark:border-zinc-700 bg-transparent px-3 py-1.5 text-sm"
          >
            {MODES.map(m => <option key={m} value={m}>{m}</option>)}
          </select>
        </div>
        {current.mode === 'oidc' && (
          <>
            <div className="space-y-1">
              <Label>OIDC Issuer URL</Label>
              <Input value={current.oidc_issuer ?? ''} onChange={e => set({ oidc_issuer: e.target.value })} />
            </div>
            <div className="space-y-1">
              <Label>Client ID</Label>
              <Input value={current.oidc_client_id ?? ''} onChange={e => set({ oidc_client_id: e.target.value })} />
            </div>
          </>
        )}
        {current.mode === 'proxy' && (
          <div className="space-y-1">
            <Label>Proxy Header (e.g. X-Forwarded-User)</Label>
            <Input value={current.proxy_header ?? ''} onChange={e => set({ proxy_header: e.target.value })} />
          </div>
        )}
      </CardContent>
    </Card>
  )
}
```

### src/components/config/UsersRolesTab.tsx

```tsx
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchUsers, deleteUser, fetchRoles } from '@/api/config'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'

export function UsersRolesTab() {
  const qc = useQueryClient()
  const { data: users } = useQuery({ queryKey: ['users'], queryFn: fetchUsers })
  const { data: roles } = useQuery({ queryKey: ['roles'], queryFn: fetchRoles })

  const delUser = useMutation({
    mutationFn: deleteUser,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  })

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader><CardTitle className="text-sm">Users</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Username</TableHead>
                <TableHead>Role</TableHead>
                <TableHead />
              </TableRow>
            </TableHeader>
            <TableBody>
              {(users ?? []).map(u => (
                <TableRow key={u.username}>
                  <TableCell className="font-mono text-xs">{u.username}</TableCell>
                  <TableCell className="text-xs">{u.role}</TableCell>
                  <TableCell>
                    <Button
                      size="sm"
                      variant="destructive"
                      className="h-6 text-xs"
                      onClick={() => delUser.mutate(u.username)}
                    >Delete</Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm">Roles</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Permissions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(roles ?? []).map(r => (
                <TableRow key={r.name}>
                  <TableCell className="font-mono text-xs">{r.name}</TableCell>
                  <TableCell className="text-xs">{r.permissions.join(', ')}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
```

### src/components/config/RetentionTab.tsx

```tsx
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchRetention, saveRetention } from '@/api/config'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'

export function RetentionTab() {
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['retention'], queryFn: fetchRetention })
  const [cfg, setCfg] = useState<{ delete_after_days?: number; archive_cron?: string } | null>(null)
  const current = cfg ?? data ?? {}

  const save = useMutation({
    mutationFn: saveRetention,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['retention'] }); setCfg(null) },
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex justify-between">
          Retention Policy
          <Button size="sm" onClick={() => save.mutate(current)} disabled={save.isPending || cfg === null}>
            {save.isPending ? 'Saving…' : 'Save'}
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1">
          <Label>Delete sessions older than (days, 0 = never)</Label>
          <Input
            type="number"
            min={0}
            value={current.delete_after_days ?? 0}
            onChange={e => setCfg({ ...current, delete_after_days: Number(e.target.value) })}
            className="w-32"
          />
        </div>
        <div className="space-y-1">
          <Label>Archive cron expression</Label>
          <Input
            value={current.archive_cron ?? ''}
            onChange={e => setCfg({ ...current, archive_cron: e.target.value })}
            placeholder="0 2 * * *"
          />
        </div>
      </CardContent>
    </Card>
  )
}
```

### src/components/config/SandboxTab.tsx

```tsx
import { useQuery } from '@tanstack/react-query'
import { fetchSandbox } from '@/api/config'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'

export function SandboxTab() {
  const { data, isPending } = useQuery({ queryKey: ['sandbox'], queryFn: fetchSandbox })

  if (isPending) return <p className="text-zinc-400 text-sm">Loading…</p>
  if (!data) return null

  return (
    <Card>
      <CardHeader><CardTitle className="text-sm">Sandbox Config</CardTitle></CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-2">
          <Switch checked={data.enabled} disabled />
          <Label>Sandbox enabled</Label>
        </div>
        <p className="text-xs text-zinc-400">
          {data.templates.length} template{data.templates.length !== 1 ? 's' : ''} defined.
          Full sandbox editor coming in a future release.
        </p>
      </CardContent>
    </Card>
  )
}
```

### src/components/config/JitTab.tsx

```tsx
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchJitPolicy, saveJitPolicy, fetchApprovalConfig, saveApprovalConfig } from '@/api/config'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'

export function JitTab() {
  const qc = useQueryClient()

  const { data: jit }      = useQuery({ queryKey: ['jit-policy'], queryFn: fetchJitPolicy })
  const { data: approval } = useQuery({ queryKey: ['approval-config'], queryFn: fetchApprovalConfig })

  const [jitDraft, setJitDraft]           = useState<typeof jit | null>(null)
  const [approvalDraft, setApprovalDraft] = useState<typeof approval | null>(null)

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
```

---

## Approvals View

### src/components/approvals/ApprovalsView.tsx

```tsx
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchApprovals, approveRequest, denyRequest } from '@/api/approvals'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Button } from '@/components/ui/button'
import { fmtDate } from '@/lib/date'

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

  if (isPending) return <div className="p-8 text-zinc-400">Loading…</div>
  if (isError)   return <div className="p-8 text-red-500">Failed to load approvals</div>

  const pending = data.filter(r => r.status === 'pending')

  return (
    <div className="p-6 overflow-y-auto h-[calc(100vh-3rem)]">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">
            Pending Approval Requests
            {pending.length > 0 && (
              <span className="ml-2 bg-red-500 text-white text-xs rounded-full px-1.5 py-0.5">
                {pending.length}
              </span>
            )}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {pending.length === 0 ? (
            <p className="text-zinc-400 text-sm">No pending requests</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Host</TableHead>
                  <TableHead>Command</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {pending.map(r => (
                  <TableRow key={r.id}>
                    <TableCell className="text-xs whitespace-nowrap">{fmtDate(r.requested_at)}</TableCell>
                    <TableCell className="font-mono text-xs">{r.user}</TableCell>
                    <TableCell className="font-mono text-xs">{r.host}</TableCell>
                    <TableCell className="font-mono text-xs truncate max-w-xs">{r.command}</TableCell>
                    <TableCell>
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          className="h-6 text-xs bg-emerald-600 hover:bg-emerald-700"
                          onClick={() => approve.mutate(r.id)}
                        >Approve</Button>
                        <Button
                          size="sm"
                          variant="destructive"
                          className="h-6 text-xs"
                          onClick={() => deny.mutate(r.id)}
                        >Deny</Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
```

---

## Verification

```bash
cd go/cmd/replay-server/ui
npm run lint    # 0 errors

npm run dev
# → /config: all 6 sub-tabs render without errors
#   - SIEM: form fields appear
#   - Auth: mode selector works
#   - Users & Roles: tables load
#   - Retention: number inputs render
#   - Sandbox: switch shows
#   - JIT / Approvals: forms render
# → /approvals: table renders (may show "No pending requests" which is fine)
```

## Output for next task
All 5 views implemented. Task 06 handles Go integration (SPA fallback),
Makefile update, cleanup of old static/ files, and RPM build.
