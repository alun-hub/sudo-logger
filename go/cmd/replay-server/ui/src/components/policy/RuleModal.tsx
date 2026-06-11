import { useState, useEffect } from 'react'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { X, Plus } from 'lucide-react'
import type { Rule, MatchPattern } from '@/api/policy'

interface Props {
  rule: Rule | null
  open: boolean
  onClose: () => void
  onSave: (rule: Rule) => void
}

export function RuleModal({ rule, open, onClose, onSave }: Props) {
  const [draft, setDraft] = useState<Rule>(emptyRule())

  useEffect(() => {
    if (rule) setDraft(JSON.parse(JSON.stringify(rule)))
    else setDraft(emptyRule())
  }, [rule, open])

  const save = () => {
    onSave(draft)
    onClose()
  }

  const updateMatch = (field: 'command' | 'content', sub: keyof MatchPattern, val: string[]) => {
    const next = { ...draft }
    if (!next[field]) next[field] = {}
    next[field]![sub] = val
    setDraft(next)
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl bg-surface border-border text-text">
        <DialogHeader>
          <DialogTitle>{rule ? 'Edit Rule' : 'Add New Rule'}</DialogTitle>
        </DialogHeader>

        <div className="grid grid-cols-3 gap-4 py-4">
          <div className="space-y-1.5">
            <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Score</label>
            <Input
              type="number"
              value={draft.score}
              onChange={e => setDraft({ ...draft, score: Number(e.target.value) })}
              className="bg-card border-border h-9"
            />
          </div>
          <div className="col-span-2 space-y-1.5">
            <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Rule ID</label>
            <Input
              value={draft.id}
              onChange={e => setDraft({ ...draft, id: e.target.value })}
              placeholder="unique_rule_name"
              className="bg-card border-border h-9 font-mono"
            />
          </div>
        </div>

        <div className="space-y-1.5">
          <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Reason (displayed in UI)</label>
          <Input
            value={draft.reason}
            onChange={e => setDraft({ ...draft, reason: e.target.value })}
            placeholder="e.g. Sensitive file access detected"
            className="bg-card border-border h-9"
          />
        </div>

        <div className="space-y-6 mt-4">
          <section className="space-y-3">
            <h3 className="text-[13px] font-semibold text-blue border-b border-blue/20 pb-1">Command Matching</h3>
            <TagInput
              label="Must contain ONE of (contains_any)"
              values={draft.command?.contains_any ?? []}
              onChange={v => updateMatch('command', 'contains_any', v)}
            />
            <TagInput
              label="AND contain ONE of (also_any)"
              values={draft.command?.also_any ?? []}
              onChange={v => updateMatch('command', 'also_any', v)}
            />
            <TagInput
              label="Base command is one of (e.g. bash, vi)"
              values={draft.command_base_any ?? []}
              onChange={v => setDraft({ ...draft, command_base_any: v })}
            />
          </section>

          <section className="space-y-3">
             <h3 className="text-[13px] font-semibold text-green border-b border-green/20 pb-1">Output (TTY) Matching</h3>
             <TagInput
              label="Output contains ONE of"
              values={draft.content?.contains_any ?? []}
              onChange={v => updateMatch('content', 'contains_any', v)}
            />
          </section>

          <section className="grid grid-cols-2 gap-8 pt-2">
             <div className="space-y-4">
                <div className="flex items-center justify-between p-2 rounded-[5px] border border-border bg-card/50">
                  <span className="text-[12px] font-medium text-text-sub">After Business Hours</span>
                  <Switch
                    checked={!!draft.after_hours}
                    onCheckedChange={v => setDraft({ ...draft, after_hours: v })}
                  />
                </div>
                <div className="flex items-center justify-between p-2 rounded-[5px] border border-border bg-card/50">
                  <span className="text-[12px] font-medium text-text-sub">Incomplete Session</span>
                  <Switch
                    checked={!!draft.incomplete}
                    onCheckedChange={v => setDraft({ ...draft, incomplete: v })}
                  />
                </div>
             </div>
             <div className="space-y-1.5">
                <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Runas User</label>
                <Input
                  value={draft.runas ?? ''}
                  onChange={e => setDraft({ ...draft, runas: e.target.value })}
                  placeholder="root"
                  className="bg-card border-border h-9 font-mono"
                />
                <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider block mt-2">Source</label>
                <Input
                  value={draft.source ?? ''}
                  onChange={e => setDraft({ ...draft, source: e.target.value })}
                  placeholder="plugin, ebpf-tty..."
                  className="bg-card border-border h-9 font-mono"
                />
             </div>
          </section>
        </div>

        <DialogFooter className="mt-8 border-t border-border pt-4">
          <Button variant="ghost" onClick={onClose} className="h-9 px-4 text-text-dim hover:text-text hover:bg-card-hover">Cancel</Button>
          <Button onClick={save} className="h-9 px-6 bg-green hover:bg-green/90 text-black font-bold">Save Rule</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function TagInput({ label, values, onChange }: { label: string, values: string[], onChange: (v: string[]) => void }) {
  const [inp, setInp] = useState('')

  const add = () => {
    const val = inp.trim()
    if (!val || values.includes(val)) return
    onChange([...values, val])
    setInp('')
  }

  const remove = (val: string) => onChange(values.filter(v => v !== val))

  return (
    <div className="space-y-1.5">
      <label className="text-[11px] font-medium text-text-dim uppercase tracking-wider">{label}</label>
      <div className="min-h-9 p-1 rounded-[5px] border border-border bg-card flex flex-wrap gap-1 items-center">
        {values.map(v => (
          <span key={v} className="bg-surface border border-border px-2 py-0.5 rounded-[3px] text-[12px] font-mono text-text flex items-center gap-1.5">
            {v}
            <button onClick={() => remove(v)} className="text-text-dim hover:text-red transition-colors"><X size={12} /></button>
          </span>
        ))}
        <input
          value={inp}
          onChange={e => setInp(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add() }
            if (e.key === 'Backspace' && !inp && values.length > 0) remove(values[values.length-1])
          }}
          className="flex-1 bg-transparent border-none outline-none text-[12px] font-mono px-2 min-w-[100px]"
          placeholder="type and press Enter..."
        />
        <button onClick={add} className="p-1 text-text-dim hover:text-green"><Plus size={16} /></button>
      </div>
    </div>
  )
}

function emptyRule(): Rule {
  return { id: '', score: 20, reason: '', command: { contains_any: [] } }
}
