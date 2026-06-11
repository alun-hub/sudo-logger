import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchAuthConfig, saveAuthConfig } from '@/api/config'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import type { AuthConfig } from '@/types/config'

const MODES = ['local', 'oidc', 'proxy'] as const

export function AuthTab() {
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['auth-config'], queryFn: fetchAuthConfig })
  const [cfg, setCfg] = useState<AuthConfig | null>(null)
  const current: AuthConfig = cfg ?? data ?? { mode: 'local' }

  const save = useMutation({
    mutationFn: saveAuthConfig,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['auth-config'] }); setCfg(null) },
  })

  const set = (patch: Partial<AuthConfig>) => setCfg({ ...current, ...patch })

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex justify-between">
          Authentication
          <Button size="sm" onClick={() => save.mutate(current)} disabled={save.isPending || cfg === null}>
            {save.isPending ? 'Saving…' : 'Save'}
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1">
          <Label>Mode</Label>
          <select
            value={current.mode}
            onChange={e => set({ mode: e.target.value as AuthConfig['mode'] })}
            className="block w-full rounded-md border border-zinc-200 dark:border-zinc-700 bg-transparent px-3 py-1.5 text-sm"
          >
            {MODES.map(m => <option key={m} value={m}>{m}</option>)}
          </select>
        </div>
        {current.mode === 'oidc' && (
          <>
            <div className="space-y-1">
              <Label>OIDC Issuer URL</Label>
              <Input value={current.oidc_issuer ?? ''} onChange={e => set({ oidc_issuer: e.target.value })} />
            </div>
            <div className="space-y-1">
              <Label>Client ID</Label>
              <Input value={current.oidc_client_id ?? ''} onChange={e => set({ oidc_client_id: e.target.value })} />
            </div>
          </>
        )}
        {current.mode === 'proxy' && (
          <div className="space-y-1">
            <Label>Proxy Header (e.g. X-Forwarded-User)</Label>
            <Input value={current.proxy_header ?? ''} onChange={e => set({ proxy_header: e.target.value })} />
          </div>
        )}
      </CardContent>
    </Card>
  )
}
