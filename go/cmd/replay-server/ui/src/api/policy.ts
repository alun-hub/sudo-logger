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

export function fetchRules(): Promise<RulesResponse> {
  return apiFetch<RulesResponse>('/api/rules')
}

export function saveRules(rules: Rule[]): Promise<{ ok: boolean }> {
  return apiFetch('/api/rules', {
    method: 'PUT',
    body: JSON.stringify({ rules }),
  })
}
