import { useState, useEffect } from 'react'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { X, Plus } from 'lucide-react'
import type { OPAMatchRule } from '@/api/opa'
import { cn } from '@/lib/utils'

interface Props {
  rule: OPAMatchRule | null
  open: boolean
  onClose: () => void
  onSave: (rule: OPAMatchRule) => void
}

export function OPARuleModal({ rule, open, onClose, onSave }: Props) {
  const [draft, setDraft] = useState<OPAMatchRule>(emptyRule())

  useEffect(() => {
    if (rule) setDraft(JSON.parse(JSON.stringify(rule)))
    else setDraft(emptyRule())
  }, [rule, open])

  const save = () => {
    onSave(draft)
    onClose()
  }

  const toggleDay = (d: number) => {
    const next = draft.weekdays || []
    if (next.includes(d)) setDraft({ ...draft, weekdays: next.filter(x => x !== d) })
    else setDraft({ ...draft, weekdays: [...next, d] })
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl bg-surface border-border text-text">
        <DialogHeader>
          <DialogTitle>{rule ? 'Edit JIT Rule' : 'Add JIT Rule'}</DialogTitle>
        </DialogHeader>

        <div className="space-y-6 py-4">
          <div className="grid grid-cols-3 gap-4">
             <div className="space-y-1.5">
                <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Action</label>
                <select
                  value={draft.action}
                  onChange={e => setDraft({ ...draft, action: e.target.value as any })}
                  className="w-full h-9 bg-card border border-border rounded-[5px] px-2 text-[13px] outline-none focus:border-green font-bold"
                >
                  <option value="challenge">CHALLENGE</option>
                  <option value="allow">ALLOW</option>
                  <option value="deny">DENY</option>
                </select>
             </div>
             <div className="col-span-2 space-y-1.5">
                <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Comment / ID</label>
                <Input
                  value={draft.comment || ''}
                  onChange={e => setDraft({ ...draft, comment: e.target.value, id: draft.id || e.target.value.toLowerCase().replace(/\s+/g, '_') })}
                  placeholder="e.g. Allow SRE team on staging"
                  className="bg-card border-border h-9"
                />
             </div>
          </div>

          <div className="grid grid-cols-2 gap-6">
             <section className="space-y-3">
                <h3 className="text-[12px] font-bold text-blue uppercase tracking-widest border-b border-blue/20 pb-1">Who & Where</h3>
                <TagInput label="Users (@group or pattern)" values={draft.users} onChange={v => setDraft({ ...draft, users: v })} />
                <TagInput label="Hosts (@group or pattern)" values={draft.hosts} onChange={v => setDraft({ ...draft, hosts: v })} />
                <TagInput label="System Groups (Live LDAP/AD)" values={draft.sys_groups || []} onChange={v => setDraft({ ...draft, sys_groups: v })} />
             </section>

             <section className="space-y-3">
                <h3 className="text-[12px] font-bold text-green uppercase tracking-widest border-b border-green/20 pb-1">Commands & Execution</h3>
                <TagInput label="Commands (glob patterns)" values={draft.commands} onChange={v => setDraft({ ...draft, commands: v })} />
                <TagInput label="Runas Users" values={draft.runas} onChange={v => setDraft({ ...draft, runas: v })} />

                <div className="pt-2 space-y-3">
                   <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Time Window (24h)</label>
                   <div className="flex items-center gap-2">
                      <Input
                        type="number" min={-1} max={23}
                        value={draft.hour_from}
                        onChange={e => setDraft({ ...draft, hour_from: Number(e.target.value) })}
                        className="bg-card border-border h-8 w-16 text-center font-mono"
                      />
                      <span className="text-text-dim">to</span>
                      <Input
                        type="number" min={-1} max={23}
                        value={draft.hour_to}
                        onChange={e => setDraft({ ...draft, hour_to: Number(e.target.value) })}
                        className="bg-card border-border h-8 w-16 text-center font-mono"
                      />
                      <span className="text-[10px] text-text-dim italic">(-1 for any)</span>
                   </div>

                   <div className="flex gap-1">
                      {['S','M','T','W','T','F','S'].map((day, i) => {
                        const active = (draft.weekdays || []).includes(i)
                        return (
                          <button
                            key={i}
                            onClick={() => toggleDay(i)}
                            className={cn(
                              "w-7 h-7 rounded-[3px] border text-[10px] font-bold transition-colors",
                              active ? "bg-green border-green text-black" : "bg-card border-border text-text-dim hover:border-border-mid"
                            )}
                          >{day}</button>
                        )
                      })}
                   </div>
                </div>
             </section>
          </div>
        </div>

        <DialogFooter className="mt-4 border-t border-border pt-4">
          <Button variant="ghost" onClick={onClose} className="h-9 px-4 text-text-dim hover:text-text hover:bg-card-hover">Cancel</Button>
          <Button onClick={save} className="h-9 px-6 bg-green hover:bg-green/90 text-black font-bold">Save Policy Rule</Button>
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
    <div className="space-y-1">
      <label className="text-[10px] font-bold text-text-dim uppercase tracking-wider">{label}</label>
      <div className="min-h-8 p-1 rounded-[4px] border border-border bg-card flex flex-wrap gap-1 items-center">
        {values.map(v => (
          <span key={v} className="bg-surface border border-border px-1.5 py-0.5 rounded-[2px] text-[11px] font-mono text-text flex items-center gap-1">
            {v}
            <button onClick={() => remove(v)} className="text-text-dim hover:text-red transition-colors"><X size={10} /></button>
          </span>
        ))}
        <input
          value={inp}
          onChange={e => setInp(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add() }
            if (e.key === 'Backspace' && !inp && values.length > 0) remove(values[values.length-1])
          }}
          className="flex-1 bg-transparent border-none outline-none text-[11px] font-mono px-1 min-w-[60px]"
          placeholder="..."
        />
      </div>
    </div>
  )
}

function emptyRule(): OPAMatchRule {
  return { id: '', comment: '', users: [], hosts: [], commands: [], runas: [], hour_from: -1, hour_to: -1, action: 'challenge', weekdays: [] }
}
