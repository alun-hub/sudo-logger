export interface SiemTLSCfg {
  ca: string
  cert: string
  key: string
}

export interface SiemConfig {
  enabled: boolean
  transport: 'https' | 'syslog' | 'stdout'
  format: 'json' | 'cef' | 'ocsf'
  https: {
    url: string
    token: string
    tls: SiemTLSCfg
  }
  syslog: {
    addr: string
    protocol: 'udp' | 'tcp' | 'tcp-tls'
    tls: SiemTLSCfg
  }
  replay_url_base: string
}

export interface GroupRoleMapping {
  group: string
  role: string
}

export interface AuthConfig {
  source: 'local' | 'oidc' | 'proxy'
  oidc: {
    issuer: string
    client_id: string
    client_secret: string
  }
  proxy: {
    user_header: string
    groups_header: string
  }
  admin_groups: string[]
  group_mappings: GroupRoleMapping[]
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
