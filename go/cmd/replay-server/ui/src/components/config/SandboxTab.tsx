import { useQuery } from '@tanstack/react-query'
import { fetchSandbox } from '@/api/config'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Switch } from '@/components/ui/switch'
import { Label } from '@/components/ui/label'

export function SandboxTab() {
  const { data, isPending } = useQuery({ queryKey: ['sandbox'], queryFn: fetchSandbox })

  if (isPending) return <p className="text-zinc-400 text-sm">Loading…</p>
  if (!data) return null

  return (
    <Card>
      <CardHeader><CardTitle className="text-sm">Sandbox Config</CardTitle></CardHeader>
      <CardContent className="space-y-4">
        <div className="flex items-center gap-2">
          <Switch checked={data.enabled} disabled />
          <Label>Sandbox enabled</Label>
        </div>
        <p className="text-xs text-zinc-400">
          {data?.templates?.length ?? 0} template{data?.templates?.length !== 1 ? 's' : ''} defined.
          Full sandbox editor coming in a future release.
        </p>
      </CardContent>
    </Card>
  )
}
