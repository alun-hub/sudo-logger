import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchAuthConfig, saveAuthConfig, fetchRoles, fetchUsers } from '@/api/config'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import type { AuthConfig, GroupRoleMapping, UserInfo } from '@/types/config'
import { Key, Globe, ShieldCheck, Plus, Trash2 } from 'lucide-react'

const MODES = ['local', 'oidc', 'proxy'] as const

const EMPTY_AUTH: AuthConfig = {
  source: 'local',
  oidc: { issuer: '', client_id: '', client_secret: '' },
  proxy: { user_header: '', groups_header: '' },
  admin_groups: [],
  group_mappings: [],
}

export function AuthTab() {
  const qc = useQueryClient()
  const { data, isPending } = useQuery({ queryKey: ['auth-config'], queryFn: fetchAuthConfig })
  const { data: roles } = useQuery({ queryKey: ['roles'], queryFn: fetchRoles })
  const { data: users } = useQuery({ queryKey: ['users'], queryFn: fetchUsers })
  const [cfg, setCfg] = useState<AuthConfig | null>(null)
  const current: AuthConfig = cfg ?? data ?? EMPTY_AUTH

  const hasLocalUsers = (users as UserInfo[] ?? []).some(u => u.source === 'local')

  const save = useMutation({
    mutationFn: saveAuthConfig,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['auth-config'] }); setCfg(null) },
  })

  const set = (patch: Partial<AuthConfig>) => setCfg({ ...current, ...patch })
  const setOidc = (patch: Partial<AuthConfig['oidc']>) =>
    set({ oidc: { ...current.oidc, ...patch } })
  const setProxy = (patch: Partial<AuthConfig['proxy']>) =>
    set({ proxy: { ...current.proxy, ...patch } })

  const addMapping = () =>
    set({ group_mappings: [...(current.group_mappings ?? []), { group: '', role: roles?.[0]?.name ?? 'viewer' }] })

  const updateMapping = (idx: number, patch: Partial<GroupRoleMapping>) => {
    const next = [...(current.group_mappings ?? [])]
    next[idx] = { ...next[idx], ...patch }
    set({ group_mappings: next })
  }

  const removeMapping = (idx: number) =>
    set({ group_mappings: (current.group_mappings ?? []).filter((_, i) => i !== idx) })

  const handleSave = () => {
    if (current.source === 'local' && !hasLocalUsers && data?.source !== 'local') {
      if (!confirm('Warning: You are switching to LOCAL authentication but you have no local users defined. You will be locked out unless you are in bootstrap mode (empty database). Continue?')) {
        return
      }
    }
    // Derive admin_groups from group_mappings for backward compat
    const adminGroups = (current.group_mappings ?? [])
      .filter(m => m.role === 'admin' && m.group)
      .map(m => m.group)
    save.mutate({ ...current, admin_groups: adminGroups })
  }

  if (isPending) return <div className="text-text-dim font-mono text-[13px]">Loading auth config…</div>

  const showMapping = current.source === 'oidc' || current.source === 'proxy'

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-border pb-2">
        <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
          <Key size={18} className="text-green" /> System Authentication
        </h2>
        <Button
          size="sm"
          onClick={handleSave}
          disabled={save.isPending || cfg === null}
          className="bg-green hover:bg-green/90 text-black font-semibold h-8 rounded-[5px]"
        >
          {save.isPending ? 'Saving…' : 'Save Auth Settings'}
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
        <div className="md:col-span-2 space-y-6">
          <div className="space-y-1.5 px-1">
            <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider">Authentication Mode</label>
            <select
              value={current.source}
              onChange={e => set({ source: e.target.value as AuthConfig['source'] })}
              className="block w-full rounded-[5px] border border-border bg-card px-3 h-10 text-[13px] outline-none focus:border-green"
            >
              {MODES.map(m => <option key={m} value={m} className="bg-surface">{m.toUpperCase()}</option>)}
            </select>
          </div>

          <div className="space-y-4 animate-in slide-in-from-top-2 duration-200">
            {current.source === 'oidc' && (
              <>
                <div className="space-y-1.5 px-1">
                  <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider flex items-center gap-2">
                    <Globe size={14} /> OIDC Issuer URL
                  </label>
                  <Input
                    value={current.oidc?.issuer ?? ''}
                    onChange={e => setOidc({ issuer: e.target.value })}
                    placeholder="https://accounts.google.com"
                    className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-1.5 px-1">
                    <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider">Client ID</label>
                    <Input
                      value={current.oidc?.client_id ?? ''}
                      onChange={e => setOidc({ client_id: e.target.value })}
                      className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                    />
                  </div>
                  <div className="space-y-1.5 px-1">
                    <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider">Client Secret</label>
                    <Input
                      type="password"
                      value={current.oidc?.client_secret ?? ''}
                      onChange={e => setOidc({ client_secret: e.target.value })}
                      placeholder="••••••••"
                      className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                    />
                  </div>
                </div>
              </>
            )}

            {current.source === 'proxy' && (
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5 px-1">
                  <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider">User Header</label>
                  <Input
                    value={current.proxy?.user_header ?? ''}
                    onChange={e => setProxy({ user_header: e.target.value })}
                    placeholder="X-Forwarded-User"
                    className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                  />
                  <p className="text-[11px] text-text-dim">Header with the authenticated username.</p>
                </div>
                <div className="space-y-1.5 px-1">
                  <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider">Groups Header</label>
                  <Input
                    value={current.proxy?.groups_header ?? ''}
                    onChange={e => setProxy({ groups_header: e.target.value })}
                    placeholder="X-Forwarded-Groups"
                    className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                  />
                  <p className="text-[11px] text-text-dim">Header with comma-separated group names.</p>
                </div>
              </div>
            )}

            {current.source === 'local' && (
               <div className="p-4 rounded-[5px] bg-card border border-border">
                  <div className="text-[13px] text-text-sub">Local mode uses the internal SQLite user database.</div>
               </div>
            )}
          </div>

          {current.source !== 'proxy' && (
            <div className="space-y-1.5 px-1 pt-4 border-t border-border/50">
              <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider">
                Step-up Re-authentication TTL
              </label>
              <Input
                type="number"
                min={1}
                value={current.step_up_ttl_minutes || ''}
                onChange={e => set({ step_up_ttl_minutes: e.target.value ? parseInt(e.target.value, 10) : undefined })}
                placeholder="10"
                className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px] max-w-[140px]"
              />
              <p className="text-[11px] text-text-dim leading-relaxed">
                Pushing sudoers/sandbox config requires re-proving your identity (password re-entry, or
                re-login at the IdP for OIDC) before it takes effect. Once verified, that proof stays valid
                for this many minutes, so editing several rules in one sitting doesn't re-prompt every time.
                Leave blank for the default (10 minutes). Has no effect in proxy mode, where there is no
                independent credential to re-check.
              </p>
            </div>
          )}

          {showMapping && (
            <div className="space-y-3 pt-4 border-t border-border/50">
              <div className="flex items-center justify-between">
                <h3 className="text-[12px] font-bold text-text uppercase tracking-widest">
                  Group Role Mapping
                </h3>
                <button
                  onClick={addMapping}
                  className="flex items-center gap-1 text-[11px] text-green hover:text-green/80 transition-colors"
                >
                  <Plus size={12} /> Add mapping
                </button>
              </div>
              <p className="text-[11px] text-text-dim">
                Map group names from {current.source === 'oidc' ? 'OIDC claims' : 'proxy headers'} to replay-server roles. First matching row wins.
              </p>
              <div className="rounded-[5px] border border-border bg-card overflow-hidden">
                <table className="w-full text-[12px]">
                  <thead className="bg-surface border-b border-border">
                    <tr>
                      <th className="text-left text-text-dim font-medium px-3 py-2 w-1/2">Group name</th>
                      <th className="text-left text-text-dim font-medium px-3 py-2">Role</th>
                      <th className="w-10"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {(current.group_mappings ?? []).length === 0 && (
                      <tr>
                        <td colSpan={3} className="text-center text-text-dim italic py-6 text-[12px]">
                          No mappings — all authenticated users get the default role.
                        </td>
                      </tr>
                    )}
                    {(current.group_mappings ?? []).map((m, i) => (
                      <tr key={i} className="border-t border-border hover:bg-card-hover">
                        <td className="px-3 py-1.5">
                          <input
                            value={m.group}
                            onChange={e => updateMapping(i, { group: e.target.value })}
                            placeholder="group-name"
                            className="w-full h-7 bg-surface border border-border rounded-[3px] px-2 font-mono text-[12px] text-text outline-none focus:border-green"
                          />
                        </td>
                        <td className="px-3 py-1.5">
                          <select
                            value={m.role}
                            onChange={e => updateMapping(i, { role: e.target.value })}
                            className="h-7 bg-surface border border-border rounded-[3px] px-2 text-[12px] text-text outline-none focus:border-green"
                          >
                            {roles?.map(r => (
                              <option key={r.name} value={r.name}>{r.name}</option>
                            ))}
                            {!roles && <option value={m.role}>{m.role}</option>}
                          </select>
                        </td>
                        <td className="px-2">
                          <button
                            onClick={() => removeMapping(i)}
                            className="p-1 text-text-dim hover:text-red transition-colors"
                          >
                            <Trash2 size={13} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        <div className="space-y-4">
           <div className="p-4 rounded-[5px] bg-blue/10 border border-blue/20 space-y-2">
             <div className="flex items-center gap-2 text-blue font-semibold text-[13px]">
               <ShieldCheck size={16} /> SSO Integration
             </div>
             <p className="text-[12px] text-text-sub leading-relaxed">
               For production environments, we recommend OIDC or Proxy authentication linked to your corporate identity provider.
             </p>
             {showMapping && (
               <p className="text-[11px] text-text-dim italic">
                 Group mappings override the default role. Any admin-mapped group also populates the legacy <code>admin_groups</code> field for backward compatibility.
               </p>
             )}
           </div>
        </div>
      </div>
    </div>
  )
}
