import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchSiemConfig, saveSiemConfig, uploadSiemCert } from '@/api/config'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'
import type { SiemConfig } from '@/types/config'

const TYPES = ['disabled', 'splunk', 'kafka', 'webhook'] as const

export function SiemTab() {
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['siem-config'], queryFn: fetchSiemConfig })
  const [cfg, setCfg] = useState<SiemConfig | null>(null)
  const current: SiemConfig = cfg ?? data ?? { type: 'disabled' }

  const save = useMutation({
    mutationFn: saveSiemConfig,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['siem-config'] }); setCfg(null) },
  })

  const certUpload = useMutation({ mutationFn: uploadSiemCert })

  const set = (patch: Partial<SiemConfig>) => setCfg({ ...current, ...patch })

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex justify-between">
          SIEM Integration
          <Button size="sm" onClick={() => save.mutate(current)} disabled={save.isPending || cfg === null}>
            {save.isPending ? 'Saving…' : 'Save'}
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1">
          <Label>Type</Label>
          <select
            value={current.type}
            onChange={e => set({ type: e.target.value as SiemConfig['type'] })}
            className="block w-full rounded-md border border-zinc-200 dark:border-zinc-700 bg-transparent px-3 py-1.5 text-sm"
          >
            {TYPES.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        {current.type !== 'disabled' && (
          <>
            <div className="space-y-1">
              <Label>URL</Label>
              <Input value={current.url ?? ''} onChange={e => set({ url: e.target.value })} />
            </div>
            <div className="space-y-1">
              <Label>{current.type === 'kafka' ? 'Topic' : 'Token / Secret'}</Label>
              <Input
                type="password"
                value={current.type === 'kafka' ? (current.topic ?? '') : (current.token ?? '')}
                onChange={e => current.type === 'kafka' ? set({ topic: e.target.value }) : set({ token: e.target.value })}
              />
            </div>
            <div className="space-y-1">
              <Label>TLS Certificate (PEM)</Label>
              <Input
                type="file"
                accept=".pem,.crt,.cer"
                onChange={e => e.target.files?.[0] && certUpload.mutate(e.target.files[0])}
              />
            </div>
          </>
        )}
      </CardContent>
    </Card>
  )
}
