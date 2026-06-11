import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchAuthConfig, saveAuthConfig } from '@/api/config'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import type { AuthConfig } from '@/types/config'
import { Key, Globe, ShieldCheck } from 'lucide-react'

const MODES = ['local', 'oidc', 'proxy'] as const

export function AuthTab() {
  const qc = useQueryClient()
  const { data, isPending } = useQuery({ queryKey: ['auth-config'], queryFn: fetchAuthConfig })
  const [cfg, setCfg] = useState<AuthConfig | null>(null)
  const current: AuthConfig = cfg ?? data ?? { mode: 'local' }

  const save = useMutation({
    mutationFn: saveAuthConfig,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['auth-config'] }); setCfg(null) },
  })

  const set = (patch: Partial<AuthConfig>) => setCfg({ ...current, ...patch })

  if (isPending) return <div className="text-text-dim font-mono text-[13px]">Loading auth config…</div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between border-b border-border pb-2">
        <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
          <Key size={18} className="text-green" /> System Authentication
        </h2>
        <Button
          size="sm"
          onClick={() => save.mutate(current)}
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
              value={current.mode}
              onChange={e => set({ mode: e.target.value as AuthConfig['mode'] })}
              className="block w-full rounded-[5px] border border-border bg-card px-3 h-10 text-[13px] outline-none focus:border-green"
            >
              {MODES.map(m => <option key={m} value={m} className="bg-surface">{m.toUpperCase()}</option>)}
            </select>
          </div>

          <div className="space-y-4 animate-in slide-in-from-top-2 duration-200">
            {current.mode === 'oidc' && (
              <>
                <div className="space-y-1.5 px-1">
                  <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider flex items-center gap-2">
                    <Globe size={14} /> OIDC Issuer URL
                  </label>
                  <Input
                    value={current.oidc_issuer ?? ''}
                    onChange={e => set({ oidc_issuer: e.target.value })}
                    placeholder="https://accounts.google.com"
                    className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                  />
                </div>
                <div className="space-y-1.5 px-1">
                  <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider">Client ID</label>
                  <Input
                    value={current.oidc_client_id ?? ''}
                    onChange={e => set({ oidc_client_id: e.target.value })}
                    className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                  />
                </div>
              </>
            )}

            {current.mode === 'proxy' && (
              <div className="space-y-1.5 px-1">
                <label className="text-[12px] font-medium text-text-sub uppercase tracking-wider">Proxy Auth Header</label>
                <Input
                  value={current.proxy_header ?? ''}
                  onChange={e => set({ proxy_header: e.target.value })}
                  placeholder="X-Forwarded-User"
                  className="bg-card border-border text-text h-10 focus:border-green font-mono text-[12px]"
                />
                <p className="text-[11px] text-text-dim">Header name containing the authenticated username from your upstream proxy.</p>
              </div>
            )}

            {current.mode === 'local' && (
               <div className="p-4 rounded-[5px] bg-card border border-border">
                  <div className="text-[13px] text-text-sub">Local mode uses the internal SQLite user database.</div>
               </div>
            )}
          </div>
        </div>

        <div className="space-y-4">
           <div className="p-4 rounded-[5px] bg-blue/10 border border-blue/20 space-y-2">
             <div className="flex items-center gap-2 text-blue font-semibold text-[13px]">
               <ShieldCheck size={16} /> SSO Integration
             </div>
             <p className="text-[12px] text-text-sub leading-relaxed">
               For production environments, we recommend OIDC or Proxy authentication linked to your corporate identity provider.
             </p>
           </div>
        </div>
      </div>
    </div>
  )
}
