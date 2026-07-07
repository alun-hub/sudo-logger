import { apiFetch, ApiError } from './client'

export interface StepUpRequired {
  authSource: string
}

/**
 * parseStepUpRequired inspects an error thrown by apiFetch and, if it's the
 * backend's {"error":"stepup_required","auth_source":"..."} 403 response
 * (see requireStepUp in go/cmd/replay-server/rbac.go), returns which auth
 * mode is in play. Returns null for any other error.
 */
export function parseStepUpRequired(err: unknown): StepUpRequired | null {
  if (!(err instanceof ApiError) || err.status !== 403) return null
  try {
    const body = JSON.parse(err.message)
    if (body?.error === 'stepup_required') {
      return { authSource: body.auth_source ?? '' }
    }
  } catch {
    // Not a JSON body -> not a step-up response.
  }
  return null
}

export function submitStepUp(password: string): Promise<void> {
  return apiFetch('/api/stepup', {
    method: 'POST',
    body: JSON.stringify({ password }),
  })
}
