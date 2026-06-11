import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Plus, Edit2, Trash2, Search } from 'lucide-react'
import { cn } from '@/lib/utils'
import { fetchRules, saveRules, type Rule } from '@/api/policy'
import { RuleModal } from './RuleModal'

export function RulesPanel() {
  const qc = useQueryClient()
  const { data, isPending } = useQuery({ queryKey: ['rules'], queryFn: fetchRules })
  const [q, setQ] = useState('')
  const [editing, setEditing] = useState<Rule | null>(null)
  const [isAddOpen, setIsAddOpen] = useState(false)

  const mutation = useMutation({
    mutationFn: saveRules,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })

  if (isPending) return <div className="text-text-dim font-mono text-[13px]">Loading rules…</div>
  if (!data) return null

  const filtered = data.rules.filter(r =>
    r.id.toLowerCase().includes(q.toLowerCase()) ||
    r.reason.toLowerCase().includes(q.toLowerCase())
  )

  const onSave = (rule: Rule) => {
    const isNew = !data.rules.find(r => r.id === rule.id)
    let next: Rule[]
    if (isNew) {
      next = [...data.rules, rule]
    } else {
      next = data.rules.map(r => r.id === rule.id ? rule : r)
    }
    mutation.mutate(next)
  }

  const deleteRule = (id: string) => {
    if (!confirm(`Are you sure you want to delete rule "${id}"?`)) return
    const next = data.rules.filter(r => r.id !== id)
    mutation.mutate(next)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-2.5 text-text-dim" size={14} />
          <input
            placeholder="Search rules…"
            value={q}
            onChange={e => setQ(e.target.value)}
            className="w-full h-9 bg-card border border-border rounded-[5px] pl-9 text-[13px] outline-none focus:border-green"
          />
        </div>
        <Button
          onClick={() => setIsAddOpen(true)}
          size="sm"
          className="bg-green hover:bg-green/90 text-black font-semibold h-9 rounded-[5px]"
        >
          <Plus size={16} className="mr-1" /> Add Rule
        </Button>
      </div>

      <div className="rounded-[5px] border border-border bg-card overflow-hidden">
        <Table className="text-[13px]">
          <TableHeader className="bg-surface">
            <TableRow className="hover:bg-transparent border-border">
              <TableHead className="w-12 text-center text-text-dim h-10">Score</TableHead>
              <TableHead className="text-text-dim h-10">ID / Reason</TableHead>
              <TableHead className="text-text-dim h-10">Match Conditions</TableHead>
              <TableHead className="w-20 h-10"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map(r => (
              <TableRow key={r.id} className="hover:bg-card-hover border-border group">
                <TableCell className="text-center font-mono">
                  <span className={cn(
                    "px-1.5 py-0.5 rounded-[3px] text-[11px] font-bold",
                    r.score >= 75 ? "text-red border border-red" :
                    r.score >= 50 ? "text-amber border border-amber" : "text-text-dim border border-border"
                  )}>
                    {r.score}
                  </span>
                </TableCell>
                <TableCell>
                  <div className="font-semibold text-text">{r.id}</div>
                  <div className="text-text-dim text-[12px]">{r.reason}</div>
                </TableCell>
                <TableCell className="font-mono text-[11px] py-3">
                  <div className="flex flex-wrap gap-x-4 gap-y-1">
                    {r.command && (
                      <span className="text-blue">command: <span className="text-text-sub">{r.command.contains_any?.join('|')}</span></span>
                    )}
                    {r.runas && <span className="text-amber">runas: <span className="text-text-sub">{r.runas}</span></span>}
                    {r.source && <span className="text-green">source: <span className="text-text-sub">{r.source}</span></span>}
                    {r.after_hours && <span className="text-red">after_hours: true</span>}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex justify-end gap-1 px-2 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      onClick={() => setEditing(r)}
                      className="p-1.5 text-text-dim hover:text-white transition-colors"
                    ><Edit2 size={14} /></button>
                    <button
                      onClick={() => deleteRule(r.id)}
                      className="p-1.5 text-text-dim hover:text-red transition-colors"
                    ><Trash2 size={14} /></button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>

      <RuleModal
        rule={editing}
        open={!!editing}
        onClose={() => setEditing(null)}
        onSave={onSave}
      />
      <RuleModal
        rule={null}
        open={isAddOpen}
        onClose={() => setIsAddOpen(false)}
        onSave={onSave}
      />
    </div>
  )
}
