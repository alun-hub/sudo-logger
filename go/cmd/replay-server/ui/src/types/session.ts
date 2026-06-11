export interface SessionInfo {
  tsid: string
  session_id?: string
  user: string
  host: string
  runas: string
  runas_uid?: number
  runas_gid?: number
  tty: string
  command: string
  resolved_command?: string
  cwd?: string
  flags?: string
  start_time: number
  duration: number
  exit_code?: number
  incomplete?: boolean
  network_outage?: boolean
  in_progress?: boolean
  risk_score: number
  risk_level: 'critical' | 'high' | 'medium' | 'low' | 'none'
  risk_reasons?: string[]
  // eBPF / divergence fields
  source?: 'plugin' | 'ebpf-tty' | 'ebpf-pkexec' | 'dbus-polkit'
  parent_session_id?: string
  has_io: boolean
  divergence_status?: 'confirmed' | 'unwitnessed' | 'missing_plugin'
  matched_session_id?: string
  caller_process?: string
  cols?: number
  rows?: number
}

export interface SessionEvent {
  t: number
  type: 3 | 4 | 'resize'
  data?: string
  cols?: number
  rows?: number
}

export interface SessionsResponse {
  sessions: SessionInfo[]
  total: number
  cursor?: string
}
