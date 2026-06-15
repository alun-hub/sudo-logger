import { apiFetch } from './client'
import type {
  SiemConfig,
  AuthConfig,
  UserInfo,
  Role,
  RetentionConfig,
  SandboxRaw,
  ApprovalConfig,
  MeResponse,
  RedactionConfig,
} from '@/types/config'

export const fetchMe = (): Promise<MeResponse> => apiFetch('/api/me')

export const login = (username: string, password: string): Promise<void> =>
  apiFetch('/api/login', { method: 'POST', body: JSON.stringify({ username, password }) })

export const fetchSiemConfig = (): Promise<SiemConfig> =>
  apiFetch('/api/siem-config').then((r: any) => r.config)
export const saveSiemConfig = (c: SiemConfig): Promise<void> =>
  apiFetch('/api/siem-config', { method: 'PUT', body: JSON.stringify({ config: c }) })
export const uploadSiemCert = (file: File): Promise<{ path: string }> => {
  const form = new FormData()
  form.append('file', file, file.name)
  return apiFetch('/api/siem-cert', { method: 'POST', body: form, headers: {} })
}

export const fetchAuthConfig = (): Promise<AuthConfig> =>
  apiFetch('/api/auth-config').then((r: any) => r.config)
export const saveAuthConfig = (c: AuthConfig): Promise<void> =>
  apiFetch('/api/auth-config', { method: 'PUT', body: JSON.stringify({ config: c }) })

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
  apiFetch('/api/retention', { method: 'PUT', body: JSON.stringify(c) })

export const fetchSandbox = (): Promise<SandboxRaw> => apiFetch('/api/sandbox')
export const saveSandbox = (content: string): Promise<void> =>
  apiFetch('/api/sandbox', { method: 'PUT', body: JSON.stringify({ content }) })
export const fetchSandboxTemplates = (): Promise<Record<string, string>> =>
  apiFetch('/api/sandbox/templates')
export const saveSandboxTemplates = (templates: Record<string, string>): Promise<void> =>
  apiFetch('/api/sandbox/templates', { method: 'PUT', body: JSON.stringify(templates) })

export const fetchApprovalConfig = (): Promise<ApprovalConfig> =>
  apiFetch('/api/approval-config').then((r: any) => r.config)
export const saveApprovalConfig = (c: ApprovalConfig): Promise<void> =>
  apiFetch('/api/approval-config', { method: 'PUT', body: JSON.stringify({ config: c }) })

export const fetchRedactionConfig = (): Promise<RedactionConfig> => apiFetch('/api/redaction-config')
export const saveRedactionConfig = (custom: string[]): Promise<void> =>
  apiFetch('/api/redaction-config', { method: 'PUT', body: JSON.stringify({ custom_patterns: custom }) })
