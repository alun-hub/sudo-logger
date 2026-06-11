import { useState, type ChangeEvent } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { TagList } from './TagList'
import {
  fetchRules, saveRules,
  fetchBlockedUsers, setBlockedUsers,
  fetchWhitelistedUsers, setWhitelistedUsers,
} from '@/api/policy'

export function PolicyEditor() {
  return (
    <div className="p-6 overflow-y-auto h-[calc(100vh-3rem)]">
      <Tabs defaultValue="rules">
        <TabsList className="mb-4">
          <TabsTrigger value="rules">Risk Rules</TabsTrigger>
          <TabsTrigger value="users">User Lists</TabsTrigger>
          <TabsTrigger value="opa" disabled>OPA Rego</TabsTrigger>
        </TabsList>
        <TabsContent value="rules"><RulesEditor /></TabsContent>
        <TabsContent value="users"><UserListsPanel /></TabsContent>
        <TabsContent value="opa">
          <p className="text-zinc-400 text-sm">OPA Rego editor — coming soon</p>
        </TabsContent>
      </Tabs>
    </div>
  )
}

function RulesEditor() {
  const qc = useQueryClient()
  const { data, isPending } = useQuery({
    queryKey: ['rules'],
    queryFn: fetchRules,
  })
  const [yaml, setYaml] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: saveRules,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })

  const current = yaml ?? data?.yaml ?? ''

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm flex items-center justify-between">
          Risk Rules (YAML)
          <Button
            size="sm"
            onClick={() => mutation.mutate(current)}
            disabled={mutation.isPending || yaml === null}
          >
            {mutation.isPending ? 'Saving…' : 'Save'}
          </Button>
        </CardTitle>
      </CardHeader>
      <CardContent>
        {isPending ? (
          <p className="text-zinc-400 text-sm">Loading…</p>
        ) : (
          <Textarea
            value={current}
            onChange={(e: ChangeEvent<HTMLTextAreaElement>) => setYaml(e.target.value)}
            className="font-mono text-xs h-96 resize-none"
            spellCheck={false}
          />
        )}
        {mutation.isError && (
          <p className="text-red-500 text-xs mt-2">Save failed</p>
        )}
      </CardContent>
    </Card>
  )
}

function UserListsPanel() {
  const qc = useQueryClient()

  const { data: blocked } = useQuery({
    queryKey: ['blocked-users'],
    queryFn: fetchBlockedUsers,
  })
  const { data: whitelisted } = useQuery({
    queryKey: ['whitelisted-users'],
    queryFn: fetchWhitelistedUsers,
  })

  const mutBlock = useMutation({
    mutationFn: setBlockedUsers,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['blocked-users'] }),
  })
  const mutWhite = useMutation({
    mutationFn: setWhitelistedUsers,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['whitelisted-users'] }),
  })

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader><CardTitle className="text-sm">Blocked Users</CardTitle></CardHeader>
        <CardContent>
          <TagList
            label="Users blocked from sudo"
            values={blocked?.users ?? []}
            onChange={users => mutBlock.mutate(users)}
          />
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle className="text-sm">Whitelisted Users</CardTitle></CardHeader>
        <CardContent>
          <TagList
            label="Users exempt from risk scoring"
            values={whitelisted?.users ?? []}
            onChange={users => mutWhite.mutate(users)}
          />
        </CardContent>
      </Card>
    </div>
  )
}
