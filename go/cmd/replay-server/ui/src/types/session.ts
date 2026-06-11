export interface SessionInfo {
  tsid: string
  user: string
  runas: string
  host: string
  command: string
  resolved_command?: string
  cwd?: string
  start_time: number
  duration: number
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
  t: number
  type: 'o' | 'i' | 'resize'
  data?: string
  cols?: number
  rows?: number
}

export interface SessionsResponse {
  sessions: SessionInfo[]
  total: number
  cursor?: string
}
