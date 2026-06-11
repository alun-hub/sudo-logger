import { apiFetch } from './client'

export interface SudoersHost {
  name: string
  isOverride: boolean
  error?: string
  inSync: boolean
  isOffline: boolean
}

export interface SudoersSnapshot {
  sha256: string
  uploaded_at: number
  content: string
}

export interface SudoersConfig {
  host: string
  content: string
  is_override: boolean
}

export function fetchSudoersHosts(): Promise<SudoersHost[]> {
  return apiFetch<SudoersHost[]>('/api/sudoers/hosts')
}

export function fetchSudoersConfig(host: string): Promise<SudoersConfig> {
  const p = new URLSearchParams()
  if (host && host !== '_default') p.set('host', host)
  return apiFetch<SudoersConfig>(`/api/sudoers/config?${p}`)
}

export function saveSudoersConfig(host: string, content: string): Promise<{ ok: boolean }> {
  const p = new URLSearchParams()
  if (host && host !== '_default') p.set('host', host)
  return apiFetch(`/api/sudoers/config?${p}`, {
    method: 'PUT',
    body: JSON.stringify({ content }),
  })
}

export function deleteSudoersOverride(host: string): Promise<{ ok: boolean }> {
  const p = new URLSearchParams()
  p.set('host', host)
  return apiFetch(`/api/sudoers/config?${p}`, { method: 'DELETE' })
}

export function fetchSudoersSnapshots(host: string): Promise<{ host: string; snapshots: SudoersSnapshot[] }> {
  const p = new URLSearchParams()
  p.set('host', host)
  return apiFetch<{ host: string; snapshots: SudoersSnapshot[] }>(`/api/sudoers/snapshots?${p}`)
}
