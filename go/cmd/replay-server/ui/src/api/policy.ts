import { apiFetch } from './client'

export interface MatchPattern {
  contains_any?: string[]
  also_any?: string[]
}

export interface Rule {
  id: string
  score: number
  reason: string
  command?: MatchPattern
  content?: MatchPattern
  command_base_any?: string[]
  runas?: string
  incomplete?: boolean
  after_hours?: boolean
  min_duration?: number
  source?: string
  exit_code?: number
}

export interface RulesResponse {
  path: string
  rules: Rule[]
}

export interface BlockedUser {
  username: string
  hosts: string[]
  reason: string
}

export interface BlockedUsersResponse {
  users: BlockedUser[]
}

export interface WhitelistedUsersResponse {
  users: string[]
}

export function fetchRules(): Promise<RulesResponse> {
  return apiFetch<RulesResponse>('/api/rules')
}

export function saveRules(rules: Rule[]): Promise<{ ok: boolean }> {
  return apiFetch('/api/rules', {
    method: 'PUT',
    body: JSON.stringify({ rules }),
  })
}

export function fetchBlockedUsers(): Promise<BlockedUsersResponse> {
  return apiFetch<BlockedUsersResponse>('/api/blocked-users')
}

export function setBlockedUsers(users: BlockedUser[]): Promise<{ ok: boolean }> {
  return apiFetch('/api/blocked-users', {
    method: 'PUT',
    body: JSON.stringify({ users }),
  })
}

export function fetchWhitelistedUsers(): Promise<WhitelistedUsersResponse> {
  return apiFetch<WhitelistedUsersResponse>('/api/whitelisted-users')
}

export function setWhitelistedUsers(users: string[]): Promise<{ ok: boolean }> {
  return apiFetch('/api/whitelisted-users', {
    method: 'PUT',
    body: JSON.stringify({ users }),
  })
}

export function fetchCompiledRego(): Promise<{ rego: string }> {
  return apiFetch<{ rego: string }>('/api/policy/rego')
}
