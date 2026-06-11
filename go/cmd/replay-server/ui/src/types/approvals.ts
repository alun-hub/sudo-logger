export interface ApprovalRequest {
  id: string
  user: string
  host: string
  command: string
  requested_at: number
  status: 'pending' | 'approved' | 'denied' | 'expired'
  approved_by?: string
  denied_by?: string
}
