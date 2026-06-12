import { apiFetch } from './client'
import type { ApprovalRequest } from '@/types/approvals'

export function fetchApprovals(): Promise<ApprovalRequest[]> {
  return apiFetch('/api/approvals')
}

export function approveRequest(id: string): Promise<void> {
  // Use path-based action to match old UI: POST /api/approvals/{id}/approve
  return apiFetch(`/api/approvals/${encodeURIComponent(id)}/approve`, {
    method: 'POST',
  })
}

export function denyRequest(id: string, reason = ''): Promise<void> {
  // Use path-based action to match old UI: POST /api/approvals/{id}/deny
  return apiFetch(`/api/approvals/${encodeURIComponent(id)}/deny`, {
    method: 'POST',
    body: JSON.stringify({ reason }),
  })
}
