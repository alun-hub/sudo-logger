# Task 04: Reports View + Policy Editor

## Context
Two of the five SPA tabs. Both are primarily data display/edit views with no
terminal component. They replace the stubs written in Task 03.

**Reports** — anomaly detection dashboard: top users by risk, top hosts by
session count, risky commands table.

**Policy** — YAML risk-rules editor, blocked/whitelisted user lists, polkit
action registry. (OPA Rego editor is deferred — leave a placeholder.)

## Working directory
`/home/alun/sudo-logger/go/cmd/replay-server/ui`

## Prerequisites
- Tasks 01–03 complete (project + API layer + Sessions view in place)

## Install shadcn/ui components

```bash
npx shadcn@latest add table card tabs textarea
```

---

## Reports View

### src/components/reports/ReportsView.tsx

```tsx
import { useQuery } from '@tanstack/react-query'
import { fetchReport, fetchAccessLog } from '@/api/reports'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { RiskBadge } from '@/components/sessions/RiskBadge'
import { fmtDate } from '@/lib/date'
import type { SessionInfo } from '@/types/session'

export function ReportsView() {
  const { data, isPending, isError } = useQuery({
    queryKey: ['report'],
    queryFn: fetchReport,
    refetchInterval: 60_000,
  })

  const { data: log } = useQuery({
    queryKey: ['access-log'],
    queryFn: fetchAccessLog,
  })

  if (isPending) return <div className="p-8 text-zinc-400">Loading…</div>
  if (isError)   return <div className="p-8 text-red-500">Failed to load report</div>

  return (
    <div className="p-6 overflow-y-auto h-[calc(100vh-3rem)] space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">

        {/* Top Users */}
        <Card>
          <CardHeader><CardTitle className="text-sm">Top Users by Risk</CardTitle></CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead className="text-right">Sessions</TableHead>
                  <TableHead className="text-right">Risk</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.top_users.map(u => (
                  <TableRow key={u.user}>
                    <TableCell className="font-mono text-xs">{u.user}</TableCell>
                    <TableCell className="text-right">{u.count}</TableCell>
                    <TableCell className="text-right">{u.risk_score.toFixed(1)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Top Hosts */}
        <Card>
          <CardHeader><CardTitle className="text-sm">Top Hosts</CardTitle></CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Host</TableHead>
                  <TableHead className="text-right">Sessions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.top_hosts.map(h => (
                  <TableRow key={h.host}>
                    <TableCell className="font-mono text-xs">{h.host}</TableCell>
                    <TableCell className="text-right">{h.count}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Risky Commands */}
        <Card>
          <CardHeader><CardTitle className="text-sm">Risky Commands</CardTitle></CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Command</TableHead>
                  <TableHead>Level</TableHead>
                  <TableHead className="text-right">Count</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.risky_commands.map((c, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono text-xs truncate max-w-[12rem]">{c.command}</TableCell>
                    <TableCell>
                      <RiskBadge level={c.level as SessionInfo['risk_level']} />
                    </TableCell>
                    <TableCell className="text-right">{c.count}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {/* Access Log */}
      {log && (
        <Card>
          <CardHeader><CardTitle className="text-sm">Recent Access Log</CardTitle></CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Time</TableHead>
                  <TableHead>User</TableHead>
                  <TableHead>Method</TableHead>
                  <TableHead>Path</TableHead>
                  <TableHead className="text-right">Status</TableHead>
                  <TableHead>IP</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {log.slice(0, 50).map((e, i) => (
                  <TableRow key={i}>
                    <TableCell className="font-mono text-xs whitespace-nowrap">{fmtDate(e.time)}</TableCell>
                    <TableCell className="text-xs">{e.user || '—'}</TableCell>
                    <TableCell className="text-xs">{e.method}</TableCell>
                    <TableCell className="font-mono text-xs">{e.path}</TableCell>
                    <TableCell className={`text-right text-xs ${e.status >= 400 ? 'text-red-500' : ''}`}>
                      {e.status}
                    </TableCell>
                    <TableCell className="font-mono text-xs">{e.remote_addr}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
```

---

## Policy Editor

### src/components/policy/TagList.tsx
Reusable component for blocked/whitelisted user lists (comma-tag input).

```tsx
import { useState } from 'react'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'

interface Props {
  label: string
  values: string[]
  onChange: (values: string[]) => void
}

export function TagList({ label, values, onChange }: Props) {
  const [draft, setDraft] = useState('')

  const add = () => {
    const v = draft.trim()
    if (v && !values.includes(v)) onChange([...values, v])
    setDraft('')
  }

  return (
    <div className="space-y-2">
      <p className="text-sm font-medium text-zinc-700 dark:text-zinc-300">{label}</p>
      <div className="flex gap-2">
        <Input
          value={draft}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && add()}
          placeholder="username"
          className="h-7 text-sm"
        />
        <Button size="sm" onClick={add} variant="outline" className="h-7">Add</Button>
      </div>
      <div className="flex flex-wrap gap-1">
        {values.map(v => (
          <span
            key={v}
            className="flex items-center gap-1 bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 text-xs px-2 py-0.5 rounded-full"
          >
            {v}
            <button
              onClick={() => onChange(values.filter(x => x !== v))}
              className="text-zinc-400 hover:text-zinc-700"
            >×</button>
          </span>
        ))}
      </div>
    </div>
  )
}
```

### src/components/policy/PolicyEditor.tsx

```tsx
import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { TagList } from './TagList'
import {
  fetchRules, saveRules,
  fetchBlockedUsers, setBlockedUsers,
  fetchWhitelistedUsers, setWhitelistedUsers,
} from '@/api/policy'

export function PolicyEditor() {
  return (
    <div className="p-6 overflow-y-auto h-[calc(100vh-3rem)]">
      <Tabs defaultValue="rules">
        <TabsList className="mb-4">
          <TabsTrigger value="rules">Risk Rules</TabsTrigger>
          <TabsTrigger value="users">User Lists</TabsTrigger>
          <TabsTrigger value="opa" disabled>OPA Rego</TabsTrigger>
        </TabsList>
        <TabsContent value="rules"><RulesEditor /></TabsContent>
        <TabsContent value="users"><UserListsPanel /></TabsContent>
        <TabsContent value="opa">
          <p className="text-zinc-400 text-sm">OPA Rego editor — coming soon</p>
        </TabsContent>
      </Tabs>
    </div>
  )
}

function RulesEditor() {
  const qc = useQueryClient()
  const { data, isPending } = useQuery({
    queryKey: ['rules'],
    queryFn: fetchRules,
  })
  const [yaml, setYaml] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: saveRules,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })

  const current = yaml ?? data?.yaml ?? ''

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex items-center justify-between">
          Risk Rules (YAML)
          <Button
            size="sm"
            onClick={() => mutation.mutate(current)}
            disabled={mutation.isPending || yaml === null}
          >
            {mutation.isPending ? 'Saving…' : 'Save'}
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isPending ? (
          <p className="text-zinc-400 text-sm">Loading…</p>
        ) : (
          <Textarea
            value={current}
            onChange={e => setYaml(e.target.value)}
            className="font-mono text-xs h-96 resize-none"
            spellCheck={false}
          />
        )}
        {mutation.isError && (
          <p className="text-red-500 text-xs mt-2">Save failed</p>
        )}
      </CardContent>
    </Card>
  )
}

function UserListsPanel() {
  const qc = useQueryClient()

  const { data: blocked } = useQuery({ queryKey: ['blocked-users'], queryFn: fetchBlockedUsers })
  const { data: whitelisted } = useQuery({ queryKey: ['whitelisted-users'], queryFn: fetchWhitelistedUsers })

  const mutBlock = useMutation({
    mutationFn: setBlockedUsers,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['blocked-users'] }),
  })
  const mutWhite = useMutation({
    mutationFn: setWhitelistedUsers,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['whitelisted-users'] }),
  })

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader><CardTitle className="text-sm">Blocked Users</CardTitle></CardHeader>
        <CardContent>
          <TagList
            label="Users blocked from sudo"
            values={blocked?.users ?? []}
            onChange={users => mutBlock.mutate(users)}
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle className="text-sm">Whitelisted Users</CardTitle></CardHeader>
        <CardContent>
          <TagList
            label="Users exempt from risk scoring"
            values={whitelisted?.users ?? []}
            onChange={users => mutWhite.mutate(users)}
          />
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
# → /reports: three tables render, no console errors
# → /policy: Rules tab shows YAML editor, User Lists tab shows tag inputs
```

## Output for next task
Reports and Policy views complete. Task 05 implements Config and Approvals views.
