import { apiFetch } from './client'
import type { SessionsResponse, SessionEvent } from '@/types/session'

export interface SessionsParams {
  q?: string
  from?: number
  to?: number
  cursor?: string
  limit?: number
}

export function fetchSessions(params: SessionsParams = {}): Promise<SessionsResponse> {
  const p = new URLSearchParams()
  if (params.q)      p.set('q', params.q)
  if (params.from)   p.set('from', String(params.from))
  if (params.to)     p.set('to', String(params.to))
  if (params.cursor) p.set('cursor', params.cursor)
  p.set('limit', String(params.limit ?? 50))
  return apiFetch<SessionsResponse>(`/api/sessions?${p}`)
}

export async function fetchSessionEvents(tsid: string): Promise<SessionEvent[]> {
  const res = await fetch(`/api/session/events?tsid=${encodeURIComponent(tsid)}`)
  if (!res.ok) throw new Error(`Failed to fetch events: ${res.status}`)
  const text = await res.text()
  return text.trim().split('\n').filter(Boolean).map(line => JSON.parse(line) as SessionEvent)
}

export function deleteSession(tsid: string): Promise<void> {
  return apiFetch(`/api/sessions/${encodeURIComponent(tsid)}`, { method: 'DELETE' })
}
