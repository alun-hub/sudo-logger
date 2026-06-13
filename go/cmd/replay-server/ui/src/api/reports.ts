import { apiFetch } from './client'

export interface ReportSummary {
  total_sessions: number
  unique_users: number
  unique_hosts: number
  incomplete_sessions: number
  long_sessions: number
  high_risk_sessions: number
  critical_sessions: number
  period_from: number
  period_to: number
}

export interface UserStat {
  user: string
  sessions: number
  hosts: number
  host_counts: Array<{ host: string; count: number }>
  avg_duration: number
  top_commands: string[]
  incomplete: number
  long_sessions: number
  high_risk: number
  critical: number
}

export interface Anomaly {
  kind: string
  tsid: string
  user: string
  host: string
  command: string
  start_time: number
  duration: number
  detail: string
  risk_score?: number
}

export interface ReportData {
  summary: ReportSummary
  per_user: UserStat[]
  anomalies: Anomaly[]
}

export interface AccessLogEntry {
  time: number
  viewer: string
  tsid: string
  replay_url?: string
}

export function fetchReport(params?: { from?: number; to?: number }): Promise<ReportData> {
  const query = new URLSearchParams()
  if (params?.from) query.set('from', params.from.toString())
  if (params?.to)   query.set('to', params.to.toString())
  const qs = query.toString()
  return apiFetch<ReportData>(`/api/report${qs ? '?' + qs : ''}`)
}

export function fetchAccessLog(): Promise<AccessLogEntry[]> {
  return apiFetch<AccessLogEntry[]>('/api/access-log')
}
