export interface ApprovalRequest {
  id: string
  user: string
  host: string
  command: string
  justification?: string
  notify_via?: string
  submitted_at: string   // ISO 8601 from Go time.Time
  expires_at?: string
  status?: 'pending' | 'approved' | 'denied' | 'expired'
  approved_by?: string
  denied_by?: string
}
