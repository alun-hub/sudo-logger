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
  source: 'local' | 'oidc' | 'proxy'
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
  days?: number
}

export interface SandboxRaw {
  content: string
  path: string
}


export interface ApprovalNotifyCfg {
  webhook_url: string
  webhook_secret: string
  mention_user: boolean
  request_channel: string
  replay_web_app_url: string
}

export interface ExemptRule {
  user: string
  hosts: string[]
}

export interface ApprovalConfig {
  enabled: boolean
  default_window: string
  pending_ttl: string
  exempt: ExemptRule[]
  notifications: ApprovalNotifyCfg
}

export interface RedactionRule {
  name: string
  description: string
  regex: string
  group: number
}

export interface RedactionConfig {
  system_rules: RedactionRule[]
  custom_patterns: string[]
}

export interface MeResponse {
  user: string
  logoutUrl?: string
  role: string
  permissions: string[]
}
