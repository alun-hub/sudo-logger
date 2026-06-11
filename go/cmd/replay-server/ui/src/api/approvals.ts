import { apiFetch } from './client'
import type { ApprovalRequest } from '@/types/approvals'

export function fetchApprovals(): Promise<ApprovalRequest[]> {
  return apiFetch('/api/approvals')
}

export function approveRequest(id: string): Promise<void> {
  return apiFetch(`/api/approvals/${encodeURIComponent(id)}`, {
    method: 'POST',
    body: JSON.stringify({ action: 'approve' }),
  })
}

export function denyRequest(id: string): Promise<void> {
  return apiFetch(`/api/approvals/${encodeURIComponent(id)}`, {
    method: 'POST',
    body: JSON.stringify({ action: 'deny' }),
  })
}
