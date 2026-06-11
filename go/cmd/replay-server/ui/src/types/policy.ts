export interface RiskRule {
  id: string
  name: string
  level: 'critical' | 'high' | 'medium' | 'low'
  match: string
  reason: string
}

export interface PolicyConfig {
  rules_yaml: string
  opa_rego?: string
  groups: Record<string, string[]>
  polkit_actions: PolkitAction[]
}

export interface PolkitAction {
  id: string
  description?: string
  level: string
}
