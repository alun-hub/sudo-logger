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
