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
  return apiFetch<BlockedPolicy>('/api/blocked-users')
}

export function saveBlockedPolicy(p: BlockedPolicy): Promise<{ ok: boolean }> {
  return apiFetch('/api/blocked-users', {
    method: 'PUT',
    body: JSON.stringify(p),
  })
}

export interface WhitelistPolicy {
  users: string[]
}

export function fetchWhitelistPolicy(): Promise<WhitelistPolicy> {
  return apiFetch<WhitelistPolicy>('/api/whitelisted-users')
}

export function saveWhitelistPolicy(p: WhitelistPolicy): Promise<{ ok: boolean }> {
  return apiFetch('/api/whitelisted-users', {
    method: 'PUT',
    body: JSON.stringify(p),
  })
}
