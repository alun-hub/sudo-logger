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
  full_name?: string
  email?: string
  created_at?: string
}

export interface Role {
  name: string
  permissions: string[]
}

export interface RetentionConfig {
  enabled?: boolean
  delete_after_days?: number
  archive_cron?: string
}

export interface SandboxRaw {
  content: string
  path: string
}

export interface JitPolicy {
  enabled: boolean
  ttl_seconds: number
  webhook_url?: string
}

export interface ApprovalConfig {
  enabled: boolean
  webhook_url?: string
  webhook_secret?: string
  bot_username?: string
  request_channel?: string
  replay_web_url?: string
  mention_user?: boolean
  default_window?: string
  ttl_seconds: number
  roles_that_can_approve: string[]
}

export interface MeResponse {
  username: string
  role: string
}
