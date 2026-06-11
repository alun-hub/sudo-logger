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
