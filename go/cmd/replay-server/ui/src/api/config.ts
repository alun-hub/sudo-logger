import { apiFetch } from './client'
import type {
  SiemConfig,
  AuthConfig,
  AuthMapping,
  UserInfo,
  Role,
  RetentionConfig,
  SandboxRaw,
  JitPolicy,
  ApprovalConfig,
  MeResponse,
} from '@/types/config'

export const fetchMe = (): Promise<MeResponse> => apiFetch('/api/me')

export const fetchSiemConfig = (): Promise<SiemConfig> => apiFetch('/api/siem-config')
export const saveSiemConfig = (c: SiemConfig): Promise<void> =>
  apiFetch('/api/siem-config', { method: 'POST', body: JSON.stringify(c) })
export const uploadSiemCert = (file: File): Promise<{ path: string }> => {
  const form = new FormData()
  form.append('file', file, file.name)
  return apiFetch('/api/siem-cert', { method: 'POST', body: form, headers: {} })
}

export const fetchAuthConfig = (): Promise<AuthConfig> => apiFetch('/api/auth-config')
export const saveAuthConfig = (c: AuthConfig): Promise<void> =>
  apiFetch('/api/auth-config', { method: 'POST', body: JSON.stringify(c) })
export const fetchAuthMapping = (): Promise<AuthMapping> => apiFetch('/api/auth-mapping')
export const saveAuthMapping = (m: AuthMapping): Promise<void> =>
  apiFetch('/api/auth-mapping', { method: 'POST', body: JSON.stringify(m) })

export const fetchUsers = (): Promise<UserInfo[]> => apiFetch('/api/users')
export const upsertUser = (u: any): Promise<void> =>
  apiFetch('/api/users', { method: 'PUT', body: JSON.stringify(u) })
export const deleteUser = (username: string): Promise<void> =>
  apiFetch(`/api/users/${encodeURIComponent(username)}`, { method: 'DELETE' })

export const fetchRoles = (): Promise<Role[]> => apiFetch('/api/roles')
export const createRole = (r: Role): Promise<void> =>
  apiFetch('/api/roles', { method: 'POST', body: JSON.stringify(r) })
export const updateRole = (name: string, r: Role): Promise<void> =>
  apiFetch(`/api/roles/${encodeURIComponent(name)}`, { method: 'PUT', body: JSON.stringify(r) })
export const deleteRole = (name: string): Promise<void> =>
  apiFetch(`/api/roles/${encodeURIComponent(name)}`, { method: 'DELETE' })

export const fetchHosts = (): Promise<{ hosts: string[] }> => apiFetch('/api/hosts')

export const fetchRetention = (): Promise<RetentionConfig> => apiFetch('/api/retention')
export const saveRetention = (c: RetentionConfig): Promise<void> =>
  apiFetch('/api/retention', { method: 'POST', body: JSON.stringify(c) })

export const fetchSandbox = (): Promise<SandboxRaw> => apiFetch('/api/sandbox')
export const saveSandbox = (content: string): Promise<void> =>
  apiFetch('/api/sandbox', { method: 'PUT', body: JSON.stringify({ content }) })
export const fetchSandboxTemplates = (): Promise<Record<string, string>> =>
  apiFetch('/api/sandbox/templates')
export const saveSandboxTemplates = (templates: Record<string, string>): Promise<void> =>
  apiFetch('/api/sandbox/templates', { method: 'PUT', body: JSON.stringify(templates) })

export const fetchJitPolicy = (): Promise<JitPolicy> => apiFetch('/api/jit-policy')
export const saveJitPolicy = (p: JitPolicy): Promise<void> =>
  apiFetch('/api/jit-policy', { method: 'POST', body: JSON.stringify(p) })

export const fetchApprovalConfig = (): Promise<ApprovalConfig> => apiFetch('/api/approval-config')
export const saveApprovalConfig = (c: ApprovalConfig): Promise<void> =>
  apiFetch('/api/approval-config', { method: 'POST', body: JSON.stringify(c) })
