import { apiFetch } from './client'

export interface OPAMatchRule {
  id: string
  comment?: string
  users: string[]
  hosts: string[]
  commands: string[]
  runas: string[]
  sys_groups?: string[]
  weekdays?: number[]
  hour_from: number
  hour_to: number
  action: 'allow' | 'challenge' | 'deny'
}

export interface OPAPolicy {
  groups: Record<string, string[]>
  rules: OPAMatchRule[]
  default_action: 'allow' | 'challenge'
  raw_rego?: string
}

export interface OPAPolicyResponse {
  policy: OPAPolicy
  rego: string
}

export function fetchOPAPolicy(): Promise<OPAPolicyResponse> {
  return apiFetch<OPAPolicyResponse>('/api/jit-policy')
}

export function saveOPAPolicy(policy: OPAPolicy): Promise<OPAPolicyResponse> {
  return apiFetch<OPAPolicyResponse>('/api/jit-policy', {
    method: 'PUT',
    body: JSON.stringify(policy),
  })
}

export interface BlockedPolicy {
  message: string
  users: BlockedUser[]
}

export interface BlockedUser {
  username: string
  hosts: string[]
  reason: string
  blocked_at?: number
}

export function fetchBlockedPolicy(): Promise<BlockedPolicy> {
  return apiFetch<any>('/api/blocked-users').then((r: any) => ({
    message: r.config?.block_message ?? '',
    users: r.config?.users ?? [],
  }))
}

export function saveBlockedPolicy(p: BlockedPolicy): Promise<{ ok: boolean }> {
  return apiFetch('/api/blocked-users', {
    method: 'PUT',
    body: JSON.stringify({ config: { block_message: p.message, users: p.users } }),
  })
}

export interface WhitelistPolicy {
  users: string[]
}

export function fetchWhitelistPolicy(): Promise<WhitelistPolicy> {
  return apiFetch<any>('/api/whitelisted-users').then((r: any) => ({
    users: ((r.config?.users ?? []) as any[]).map((u: any) =>
      typeof u === 'string' ? u : u.username
    ),
  }))
}

export function saveWhitelistPolicy(p: WhitelistPolicy): Promise<{ ok: boolean }> {
  return apiFetch('/api/whitelisted-users', {
    method: 'PUT',
    body: JSON.stringify({
      config: { users: p.users.map(u => ({ username: u, hosts: [], reason: '' })) },
    }),
  })
}
