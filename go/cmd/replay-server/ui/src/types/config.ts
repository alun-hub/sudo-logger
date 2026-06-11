export interface SiemConfig {
  type: 'splunk' | 'kafka' | 'webhook' | 'disabled'
  url?: string
  token?: string
  topic?: string
}

export interface AuthConfig {
  mode: 'local' | 'oidc' | 'proxy'
  oidc_issuer?: string
  oidc_client_id?: string
  proxy_header?: string
  admin_users?: string[]
}

export interface AuthMapping {
  group_role_map: Record<string, string>
}

export interface UserInfo {
  username: string
  role: string
  created_at?: string
}

export interface Role {
  name: string
  permissions: string[]
}

export interface RetentionConfig {
  delete_after_days?: number
  archive_cron?: string
}

export interface SandboxConfig {
  enabled: boolean
  templates: SandboxTemplate[]
}

export interface SandboxTemplate {
  name: string
  yaml: string
}

export interface JitPolicy {
  enabled: boolean
  ttl_seconds: number
  webhook_url?: string
}

export interface ApprovalConfig {
  enabled: boolean
  webhook_url?: string
  ttl_seconds: number
  roles_that_can_approve: string[]
}

export interface MeResponse {
  username: string
  role: string
}
