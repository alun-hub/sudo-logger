import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchRetention, saveRetention } from '@/api/config'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { Label } from '@/components/ui/label'

export function RetentionTab() {
  const qc = useQueryClient()
  const { data } = useQuery({ queryKey: ['retention'], queryFn: fetchRetention })
  const [cfg, setCfg] = useState<{ delete_after_days?: number; archive_cron?: string } | null>(null)
  const current = cfg ?? data ?? {}

  const save = useMutation({
    mutationFn: saveRetention,
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['retention'] }); setCfg(null) },
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex justify-between">
          Retention Policy
          <Button size="sm" onClick={() => save.mutate(current)} disabled={save.isPending || cfg === null}>
            {save.isPending ? 'Saving…' : 'Save'}
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1">
          <Label>Delete sessions older than (days, 0 = never)</Label>
          <Input
            type="number"
            min={0}
            value={current.delete_after_days ?? 0}
            onChange={e => setCfg({ ...current, delete_after_days: Number(e.target.value) })}
            className="w-32"
          />
        </div>
        <div className="space-y-1">
          <Label>Archive cron expression</Label>
          <Input
            value={current.archive_cron ?? ''}
            onChange={e => setCfg({ ...current, archive_cron: e.target.value })}
            placeholder="0 2 * * *"
          />
        </div>
      </CardContent>
    </Card>
  )
}
