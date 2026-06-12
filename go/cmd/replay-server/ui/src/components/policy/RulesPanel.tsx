import { useState, useMemo } from 'react'
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
  const [sortCol, setSortCol] = useState('score')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  const mutation = useMutation({
    mutationFn: saveRules,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })

  if (isPending) return <div className="text-text-dim font-mono text-[13px]">Loading rules…</div>
  if (!data) return null

  const filtered = useMemo(() => {
    let list = data.rules.filter(r =>
      r.id.toLowerCase().includes(q.toLowerCase()) ||
      r.reason.toLowerCase().includes(q.toLowerCase())
    )
    list.sort((a, b) => {
      const vA = (a as any)[sortCol]
      const vB = (b as any)[sortCol]
      if (vA < vB) return sortDir === 'asc' ? -1 : 1
      if (vA > vB) return sortDir === 'asc' ? 1 : -1
      return 0
    })
    return list
  }, [data.rules, q, sortCol, sortDir])

  const toggleSort = (col: string) => {
    if (sortCol === col) setSortDir(sortDir === 'asc' ? 'desc' : 'asc')
    else { setSortCol(col); setSortDir('desc') }
  }

  const onSave = (rule: Rule) => {
    const isNew = !data.rules.find(r => r.id === rule.id)
    let next: Rule[]
    if (isNew) {
      next = [...data.rules, rule]
    } else {
      next = data.rules.map(r => r.id === rule.id ? rule : r)
    }
    mutation.mutate({ rules: next })
  }

  const onDelete = (id: string) => {
    if (!confirm(`Delete rule ${id}?`)) return
    mutation.mutate({ rules: data.rules.filter(r => r.id !== id) })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="relative w-72">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-dim" />
          <input
            placeholder="Search rules…"
            value={q}
            onChange={e => setQ(e.target.value)}
            className="h-9 w-full bg-card border border-border rounded-[5px] pl-9 pr-4 text-[13px] outline-none focus:border-green transition-all"
          />
        </div>
        <Button
          onClick={() => setIsAddOpen(true)}
          className="bg-green hover:bg-green/90 text-black font-bold h-9 rounded-[4px] px-6"
        >
          <Plus size={16} className="mr-1.5" /> Add Risk Rule
        </Button>
      </div>

      <div className="rounded-[5px] border border-border bg-card overflow-hidden shadow-xl">
        <Table className="text-[13px]">
          <TableHeader className="bg-surface/80 backdrop-blur-sm">
            <TableRow className="hover:bg-transparent border-border">
              <TableHead
                className="w-24 text-center text-text-dim h-11 cursor-pointer hover:text-text transition-colors uppercase tracking-tighter text-[11px] font-bold"
                onClick={() => toggleSort('score')}
              >
                <div className="flex items-center justify-center gap-1">
                  Score {sortCol === 'score' && (sortDir === 'asc' ? '↑' : '↓')}
                </div>
              </TableHead>
              <TableHead
                className="text-text-dim h-11 cursor-pointer hover:text-text transition-colors uppercase tracking-tighter text-[11px] font-bold"
                onClick={() => toggleSort('id')}
              >
                <div className="flex items-center gap-1">
                  ID / Reason {sortCol === 'id' && (sortDir === 'asc' ? '↑' : '↓')}
                </div>
              </TableHead>
              <TableHead className="text-text-dim h-11 uppercase tracking-tighter text-[11px] font-bold">Match Conditions</TableHead>
              <TableHead className="w-20 h-11"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filtered.map(r => (
              <TableRow key={r.id} className="hover:bg-card-hover border-border group transition-colors h-12">
                <TableCell className="text-center">
                  <span className={cn(
                    "px-2 py-0.5 rounded-[3px] font-black text-[11px]",
                    r.score >= 75 ? "bg-red text-white" :
                    r.score >= 40 ? "bg-amber text-black" : "bg-blue text-white"
                  )}>
                    {r.score}
                  </span>
                </TableCell>
                <TableCell>
                  <div className="flex flex-col">
                    <span className="font-mono font-bold text-text">{r.id}</span>
                    <span className="text-[11px] text-text-dim italic">{r.reason}</span>
                  </div>
                </TableCell>
                <TableCell className="font-mono text-[11px] text-text-dim">
                  <div className="flex flex-wrap gap-x-4 gap-y-1">
                    {r.command?.contains_any?.length > 0 && <span>cmd: <span className="text-blue">{r.command.contains_any.join(', ')}</span></span>}
                    {r.content?.contains_any?.length > 0 && <span>tty: <span className="text-green">{r.content.contains_any.join(', ')}</span></span>}
                    {r.after_hours && <span className="text-amber">after-hours</span>}
                    {r.runas && <span>runas: <span className="text-amber">{r.runas}</span></span>}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <button
                      onClick={() => setEditing(r)}
                      className="p-1.5 text-text-dim hover:text-white"
                    ><Edit2 size={14} /></button>
                    <button
                      onClick={() => onDelete(r.id)}
                      className="p-1.5 text-text-dim hover:text-red"
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
