# Task 02: API Layer + TypeScript Types

## Context
The replay-server exposes ~22 REST endpoints. This task creates a typed API
client in `src/api/` and TypeScript type definitions in `src/types/`.
No React components are written — this is pure TS data access code.

The Go server runs on `:8080`. In dev, Vite proxies `/api` there.
In production, the built files are served directly by the Go server.

## Working directory
`/home/alun/sudo-logger/go/cmd/replay-server/ui`

## Prerequisites
Task 01 must be complete (Vite project exists).

## File structure to create

```
src/
  types/
    session.ts
    policy.ts
    config.ts
    approvals.ts
  api/
    client.ts
    sessions.ts
    reports.ts
    policy.ts
    config.ts
    approvals.ts
```

---

## src/types/session.ts

```ts
export interface SessionInfo {
  tsid: string
  user: string
  runas: string
  host: string
  command: string
  resolved_command?: string
  cwd?: string
  start_time: number        // unix timestamp
  duration: number          // seconds
  exit_code?: number
  has_io: boolean
  source: 'sudo' | 'pkexec'
  risk_score: number
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'none'
  risk_reasons: string[]
  incomplete?: boolean
  in_progress?: boolean
  network_outage?: boolean
  divergence_status?: string
  caller_process?: string
  parent_session_id?: string
}

export interface SessionEvent {
  t: number       // offset in seconds from session start
  type: 'o' | 'i' | 'resize'
  data?: string   // base64-encoded
  cols?: number
  rows?: number
}

export interface SessionsResponse {
  sessions: SessionInfo[]
  total: number
  cursor?: string
}
```

## src/types/policy.ts

```ts
export interface RiskRule {
  id: string
  name: string
  level: 'critical' | 'high' | 'medium' | 'low'
  match: string    // glob/regex pattern
  reason: string
}

export interface PolicyConfig {
  rules_yaml: string
  opa_rego?: string
  groups: Record<string, string[]>
  polkit_actions: PolkitAction[]
}

export interface PolkitAction {
  id: string
  description?: string
  level: string
}
```

## src/types/config.ts

```ts
export interface SiemConfig {
  type: 'splunk' | 'kafka' | 'webhook' | 'disabled'
  url?: string
  token?: string
  topic?: string
}

export interface AuthConfig {
  mode: 'local' | 'oidc' | 'proxy'
  oidc_issuer?: string
  oidc_client_id?: string
  proxy_header?: string
  admin_users?: string[]
}

export interface AuthMapping {
  group_role_map: Record<string, string>
}

export interface UserInfo {
  username: string
  role: string
  created_at?: string
}

export interface Role {
  name: string
  permissions: string[]
}

export interface RetentionConfig {
  delete_after_days?: number
  archive_cron?: string
}

export interface SandboxConfig {
  enabled: boolean
  templates: SandboxTemplate[]
}

export interface SandboxTemplate {
  name: string
  yaml: string
}

export interface JitPolicy {
  enabled: boolean
  ttl_seconds: number
  webhook_url?: string
}

export interface ApprovalConfig {
  enabled: boolean
  webhook_url?: string
  ttl_seconds: number
  roles_that_can_approve: string[]
}

export interface MeResponse {
  username: string
  role: string
}
```

## src/types/approvals.ts

```ts
export interface ApprovalRequest {
  id: string
  user: string
  host: string
  command: string
  requested_at: number
  status: 'pending' | 'approved' | 'denied' | 'expired'
  approved_by?: string
}
```

---

## src/api/client.ts

```ts
class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
    this.name = 'ApiError'
  }
}

export async function apiFetch<T>(
  path: string,
  init?: RequestInit,
): Promise<T> {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  })
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText)
    throw new ApiError(res.status, text)
  }
  // 204 No Content
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export { ApiError }
```

## src/api/sessions.ts

```ts
import { apiFetch } from './client'
import type { SessionsResponse, SessionEvent } from '@/types/session'

export interface SessionsParams {
  q?: string
  from?: number    // unix
  to?: number      // unix
  cursor?: string
  limit?: number
}

export function fetchSessions(params: SessionsParams = {}): Promise<SessionsResponse> {
  const p = new URLSearchParams()
  if (params.q)      p.set('q', params.q)
  if (params.from)   p.set('from', String(params.from))
  if (params.to)     p.set('to', String(params.to))
  if (params.cursor) p.set('cursor', params.cursor)
  if (params.limit)  p.set('limit', String(params.limit ?? 50))
  return apiFetch<SessionsResponse>(`/api/sessions?${p}`)
}

export async function fetchSessionEvents(tsid: string): Promise<SessionEvent[]> {
  const res = await fetch(`/api/session/events?tsid=${encodeURIComponent(tsid)}`)
  if (!res.ok) throw new Error(`Failed to fetch events: ${res.status}`)
  const text = await res.text()
  return text.trim().split('\n').filter(Boolean).map(line => JSON.parse(line))
}

export function deleteSession(tsid: string): Promise<void> {
  return apiFetch(`/api/sessions/${encodeURIComponent(tsid)}`, { method: 'DELETE' })
}
```

## src/api/reports.ts

```ts
import { apiFetch } from './client'

export interface ReportData {
  top_users: Array<{ user: string; count: number; risk_score: number }>
  top_hosts: Array<{ host: string; count: number }>
  risky_commands: Array<{ command: string; count: number; level: string }>
}

export interface AccessLogEntry {
  time: number
  user: string
  path: string
  method: string
  status: number
  remote_addr: string
}

export function fetchReport(): Promise<ReportData> {
  return apiFetch<ReportData>('/api/report')
}

export function fetchAccessLog(): Promise<AccessLogEntry[]> {
  return apiFetch<AccessLogEntry[]>('/api/access-log')
}
```

## src/api/policy.ts

```ts
import { apiFetch } from './client'

export function fetchRules(): Promise<{ yaml: string }> {
  return apiFetch('/api/rules')
}

export function saveRules(yaml: string): Promise<void> {
  return apiFetch('/api/rules', { method: 'POST', body: JSON.stringify({ yaml }) })
}

export function fetchBlockedUsers(): Promise<{ users: string[] }> {
  return apiFetch('/api/blocked-users')
}

export function setBlockedUsers(users: string[]): Promise<void> {
  return apiFetch('/api/blocked-users', { method: 'POST', body: JSON.stringify({ users }) })
}

export function fetchWhitelistedUsers(): Promise<{ users: string[] }> {
  return apiFetch('/api/whitelisted-users')
}

export function setWhitelistedUsers(users: string[]): Promise<void> {
  return apiFetch('/api/whitelisted-users', { method: 'POST', body: JSON.stringify({ users }) })
}

export function fetchSudoersHosts(): Promise<{ hosts: string[] }> {
  return apiFetch('/api/sudoers/hosts')
}

export function fetchSudoersSnapshots(): Promise<unknown[]> {
  return apiFetch('/api/sudoers/snapshots')
}

export function fetchSudoersConfig(): Promise<unknown> {
  return apiFetch('/api/sudoers/config')
}
```

## src/api/config.ts

```ts
import { apiFetch } from './client'
import type {
  SiemConfig, AuthConfig, AuthMapping, UserInfo, Role,
  RetentionConfig, SandboxConfig, SandboxTemplate, JitPolicy,
  ApprovalConfig, MeResponse,
} from '@/types/config'

export const fetchMe = (): Promise<MeResponse> => apiFetch('/api/me')

// SIEM
export const fetchSiemConfig = (): Promise<SiemConfig> => apiFetch('/api/siem-config')
export const saveSiemConfig = (c: SiemConfig): Promise<void> =>
  apiFetch('/api/siem-config', { method: 'POST', body: JSON.stringify(c) })
export const uploadSiemCert = (file: File): Promise<void> => {
  const form = new FormData()
  form.append('cert', file)
  return apiFetch('/api/siem-cert', { method: 'POST', body: form, headers: {} })
}

// Auth
export const fetchAuthConfig = (): Promise<AuthConfig> => apiFetch('/api/auth-config')
export const saveAuthConfig = (c: AuthConfig): Promise<void> =>
  apiFetch('/api/auth-config', { method: 'POST', body: JSON.stringify(c) })
export const fetchAuthMapping = (): Promise<AuthMapping> => apiFetch('/api/auth-mapping')
export const saveAuthMapping = (m: AuthMapping): Promise<void> =>
  apiFetch('/api/auth-mapping', { method: 'POST', body: JSON.stringify(m) })

// Users
export const fetchUsers = (): Promise<UserInfo[]> => apiFetch('/api/users')
export const createUser = (u: { username: string; password: string; role: string }): Promise<void> =>
  apiFetch('/api/users', { method: 'POST', body: JSON.stringify(u) })
export const deleteUser = (username: string): Promise<void> =>
  apiFetch(`/api/users/${encodeURIComponent(username)}`, { method: 'DELETE' })

// Roles
export const fetchRoles = (): Promise<Role[]> => apiFetch('/api/roles')
export const createRole = (r: Role): Promise<void> =>
  apiFetch('/api/roles', { method: 'POST', body: JSON.stringify(r) })
export const updateRole = (name: string, r: Role): Promise<void> =>
  apiFetch(`/api/roles/${encodeURIComponent(name)}`, { method: 'PUT', body: JSON.stringify(r) })
export const deleteRole = (name: string): Promise<void> =>
  apiFetch(`/api/roles/${encodeURIComponent(name)}`, { method: 'DELETE' })

// Hosts
export const fetchHosts = (): Promise<{ hosts: string[] }> => apiFetch('/api/hosts')

// Retention
export const fetchRetention = (): Promise<RetentionConfig> => apiFetch('/api/retention')
export const saveRetention = (c: RetentionConfig): Promise<void> =>
  apiFetch('/api/retention', { method: 'POST', body: JSON.stringify(c) })

// Sandbox
export const fetchSandbox = (): Promise<SandboxConfig> => apiFetch('/api/sandbox')
export const saveSandbox = (c: SandboxConfig): Promise<void> =>
  apiFetch('/api/sandbox', { method: 'POST', body: JSON.stringify(c) })
export const fetchSandboxTemplates = (): Promise<SandboxTemplate[]> =>
  apiFetch('/api/sandbox/templates')

// JIT
export const fetchJitPolicy = (): Promise<JitPolicy> => apiFetch('/api/jit-policy')
export const saveJitPolicy = (p: JitPolicy): Promise<void> =>
  apiFetch('/api/jit-policy', { method: 'POST', body: JSON.stringify(p) })

// Approval config
export const fetchApprovalConfig = (): Promise<ApprovalConfig> => apiFetch('/api/approval-config')
export const saveApprovalConfig = (c: ApprovalConfig): Promise<void> =>
  apiFetch('/api/approval-config', { method: 'POST', body: JSON.stringify(c) })
```

## src/api/approvals.ts

```ts
import { apiFetch } from './client'
import type { ApprovalRequest } from '@/types/approvals'

export const fetchApprovals = (): Promise<ApprovalRequest[]> => apiFetch('/api/approvals')

export const approveRequest = (id: string): Promise<void> =>
  apiFetch(`/api/approvals/${encodeURIComponent(id)}`, { method: 'POST', body: JSON.stringify({ action: 'approve' }) })

export const denyRequest = (id: string): Promise<void> =>
  apiFetch(`/api/approvals/${encodeURIComponent(id)}`, { method: 'POST', body: JSON.stringify({ action: 'deny' }) })
```

---

## src/lib/date.ts

```ts
// Format unix timestamp as yyyy-mm-dd HH:mm (24h)
export function fmtDate(unix: number): string {
  const d = new Date(unix * 1000)
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

// Format duration in seconds as HH:mm:ss or mm:ss
export function fmtDuration(s: number): string {
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = Math.floor(s % 60)
  const p = (n: number) => String(n).padStart(2, '0')
  return h > 0 ? `${h}:${p(m)}:${p(sec)}` : `${p(m)}:${p(sec)}`
}
```

## src/lib/utils.ts

```ts
import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
```

---

## Verification

```bash
cd go/cmd/replay-server/ui
npm run lint
# → 0 errors
```

No runtime test needed yet — all pure TypeScript.

## Output for next task
API layer complete. Task 03 builds the AppShell (layout + navigation) and
Sessions view (session list + terminal player).
