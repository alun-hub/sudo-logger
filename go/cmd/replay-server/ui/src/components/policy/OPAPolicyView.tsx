import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchOPAPolicy, saveOPAPolicy, type OPAMatchRule, type OPAPolicy } from '@/api/opa'
import { Button } from '@/components/ui/button'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Plus, Edit2, Trash2, ShieldCheck, Save, RotateCcw, X } from 'lucide-react'
import { cn } from '@/lib/utils'
import { OPARuleModal } from './OPARuleModal'

export function OPAPolicyView() {
  const qc = useQueryClient()
  const { data, isPending } = useQuery({ queryKey: ['opa-policy'], queryFn: fetchOPAPolicy })
  const [draft, setDraft] = useState<OPAPolicy | null>(null)

  const [editRule, setEditRule] = useState<{ rule: OPAMatchRule, idx: number } | null>(null)
  const [isAddOpen, setIsAddOpen] = useState(false)

  const [editGroup, setEditGroup] = useState<{ name: string, members: string[] } | null>(null)

  const mut = useMutation({
    mutationFn: saveOPAPolicy,
    onSuccess: (res) => {
      qc.setQueryData(['opa-policy'], res)
      setDraft(null)
    },
  })

  if (isPending || !data) return <div className="p-8 text-text-dim font-mono text-[13px]">Loading JIT policy…</div>

  const current = draft ?? data.policy
  const isDirty = draft !== null

  const set = (patch: Partial<OPAPolicy>) => setDraft({ ...current, ...patch })

  const onSaveRule = (rule: OPAMatchRule) => {
    let nextRules = [...current.rules]
    if (editRule) {
      nextRules[editRule.idx] = rule
    } else {
      nextRules.push(rule)
    }
    set({ rules: nextRules })
    setEditRule(null)
    setIsAddOpen(false)
  }

  const deleteRule = (idx: number) => {
    if (!confirm('Delete this policy rule?')) return
    const nextRules = current.rules.filter((_, i) => i !== idx)
    set({ rules: nextRules })
  }

  const onSaveGroup = (name: string, members: string[]) => {
    const nextGroups = { ...current.groups, [name]: members }
    set({ groups: nextGroups })
    setEditGroup(null)
  }

  const deleteGroup = (name: string) => {
    if (!confirm(`Delete group @${name}?`)) return
    const nextGroups = { ...current.groups }
    delete nextGroups[name]
    set({ groups: nextGroups })
  }

  return (
    <div className="flex flex-col h-full bg-bg text-text-sub overflow-hidden animate-in fade-in duration-200">
      <div className="px-6 py-4 border-b border-border bg-surface/50 flex items-center justify-between shrink-0">
        <div className="space-y-1">
          <h2 className="text-[16px] font-bold text-text flex items-center gap-2">
            <ShieldCheck size={18} className="text-green" /> OPA JIT Policy
          </h2>
          <p className="text-[12px] text-text-dim">Define who can run sudo without a justification (allow), who must provide one (challenge), and who is blocked (deny).</p>
        </div>
        <div className="flex items-center gap-2">
           {isDirty && (
             <Button variant="ghost" size="sm" onClick={() => setDraft(null)} className="h-8 text-text-dim hover:text-text">
               <RotateCcw size={14} className="mr-1.5" /> Discard
             </Button>
           )}
           <Button
            size="sm"
            disabled={!isDirty || mut.isPending}
            onClick={() => mut.mutate(current)}
            className="h-8 bg-green hover:bg-green/90 text-black font-bold px-4 rounded-[4px]"
          >
            <Save size={14} className="mr-1.5" /> {mut.isPending ? 'Saving...' : 'Save Policy'}
          </Button>
        </div>
      </div>

      <Tabs defaultValue="rules" className="flex-1 flex flex-col overflow-hidden">
        <div className="px-6 border-b border-border bg-surface shrink-0">
          <TabsList className="h-[44px] bg-transparent p-0 gap-4">
            <TabsTrigger value="rules" className="h-full rounded-none border-b-2 border-transparent data-[state=active]:border-green data-[state=active]:bg-transparent data-[state=active]:text-green px-0 text-[13px] font-medium transition-all gap-2">Rules</TabsTrigger>
            <TabsTrigger value="groups" className="h-full rounded-none border-b-2 border-transparent data-[state=active]:border-green data-[state=active]:bg-transparent data-[state=active]:text-green px-0 text-[13px] font-medium transition-all gap-2">Groups</TabsTrigger>
            <TabsTrigger value="rego" className="h-full rounded-none border-b-2 border-transparent data-[state=active]:border-green data-[state=active]:bg-transparent data-[state=active]:text-green px-0 text-[13px] font-medium transition-all gap-2">Compiled Rego</TabsTrigger>
          </TabsList>
        </div>

        <div className="flex-1 overflow-y-auto p-6">
          <TabsContent value="rules" className="m-0 space-y-6 animate-in slide-in-from-left-2 duration-200">
             <div className="flex items-center gap-4 bg-card border border-border p-3 rounded-[5px] w-fit">
                <label className="text-[12px] font-medium text-text-dim">Default action if no rules match:</label>
                <select
                  value={current.default_action}
                  onChange={e => set({ default_action: e.target.value as any })}
                  className="bg-surface border border-border rounded-[4px] px-2 py-1 text-[12px] outline-none focus:border-green text-text font-bold"
                >
                  <option value="challenge">Challenge (ask why)</option>
                  <option value="allow">Allow (no prompt)</option>
                </select>
             </div>

             <div className="rounded-[5px] border border-border bg-card overflow-hidden">
                <Table className="text-[13px]">
                  <TableHeader className="bg-surface">
                    <TableRow className="hover:bg-transparent border-border">
                      <TableHead className="text-text-dim h-10 w-24">Action</TableHead>
                      <TableHead className="text-text-dim h-10">Conditions</TableHead>
                      <TableHead className="text-text-dim h-10">Comment</TableHead>
                      <TableHead className="w-16 h-10"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {current.rules.map((r, i) => (
                      <TableRow key={i} className="hover:bg-card-hover border-border group">
                        <TableCell>
                          <span className={cn(
                            "px-2 py-0.5 rounded-[3px] text-[10px] font-bold uppercase",
                            r.action === 'deny' ? "bg-red text-white" :
                            r.action === 'allow' ? "bg-green text-black" : "bg-blue text-white"
                          )}>
                            {r.action}
                          </span>
                        </TableCell>
                        <TableCell className="font-mono text-[11px] py-3">
                           <div className="flex flex-wrap gap-x-4 gap-y-1">
                              {r.users?.length > 0 && <span className="text-blue">users: <span className="text-text-sub">{r.users.join(', ')}</span></span>}
                              {r.hosts?.length > 0 && <span className="text-amber">hosts: <span className="text-text-sub">{r.hosts.join(', ')}</span></span>}
                              {r.commands?.length > 0 && <span className="text-green">commands: <span className="text-text-sub">{r.commands.join(', ')}</span></span>}
                              {(r.hour_from >= 0 || r.hour_to >= 0) && <span className="text-red">time: <span className="text-text-sub">{r.hour_from}:00-{r.hour_to}:00</span></span>}
                           </div>
                        </TableCell>
                        <TableCell className="text-text-dim italic">{r.comment || '—'}</TableCell>
                        <TableCell>
                           <div className="flex justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                              <button onClick={() => setEditRule({ rule: r, idx: i })} className="p-1.5 text-text-dim hover:text-white"><Edit2 size={14} /></button>
                              <button onClick={() => deleteRule(i)} className="p-1.5 text-text-dim hover:text-red"><Trash2 size={14} /></button>
                           </div>
                        </TableCell>
                      </TableRow>
                    ))}
                    {current.rules.length === 0 && (
                      <TableRow><TableCell colSpan={4} className="h-32 text-center text-text-dim italic">No JIT rules defined. Falling back to default action.</TableCell></TableRow>
                    )}
                  </TableBody>
                </Table>
             </div>
             <Button onClick={() => setIsAddOpen(true)} size="sm" variant="outline" className="h-9 border-border text-text-sub"><Plus size={16} className="mr-1" /> Add Policy Rule</Button>
          </TabsContent>

          <TabsContent value="groups" className="m-0 space-y-6 animate-in slide-in-from-left-2 duration-200">
             <div className="bg-surface/50 border border-border p-4 rounded-[5px] space-y-2">
                <p className="text-[12px] text-text-sub">Named groups of users, hosts or roles. Reference with <code>@groupname</code> in policy fields.</p>
                <p className="text-[11px] text-text-dim italic">System groups (LDAP/AD) are resolved live — add them directly in rules without defining them here.</p>
             </div>

             <div className="rounded-[5px] border border-border bg-card overflow-hidden max-w-4xl">
                <Table className="text-[13px]">
                  <TableHeader className="bg-surface">
                    <TableRow className="hover:bg-transparent border-border">
                      <TableHead className="text-text-dim h-10 w-48">Name (use as @name)</TableHead>
                      <TableHead className="text-text-dim h-10">Members (usernames, globs)</TableHead>
                      <TableHead className="w-16 h-10"></TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {Object.entries(current.groups || {}).map(([name, members]) => (
                      <TableRow key={name} className="hover:bg-card-hover border-border group">
                        <TableCell className="font-mono font-bold text-blue">@{name}</TableCell>
                        <TableCell className="font-mono text-[12px] text-text-sub">{members.join(', ')}</TableCell>
                        <TableCell>
                           <div className="flex justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                              <button onClick={() => setEditGroup({ name, members })} className="p-1.5 text-text-dim hover:text-white"><Edit2 size={14} /></button>
                              <button onClick={() => deleteGroup(name)} className="p-1.5 text-text-dim hover:text-red"><Trash2 size={14} /></button>
                           </div>
                        </TableCell>
                      </TableRow>
                    ))}
                    {Object.keys(current.groups || {}).length === 0 && (
                      <TableRow><TableCell colSpan={3} className="h-32 text-center text-text-dim italic">No custom groups defined.</TableCell></TableRow>
                    )}
                  </TableBody>
                </Table>
             </div>
             <Button
                onClick={() => {
                   const name = prompt('Group name (without @):')
                   if (name) onSaveGroup(name.toLowerCase(), [])
                }}
                size="sm" variant="outline" className="h-9 border-border text-text-sub"
             >
                <Plus size={16} className="mr-1" /> Add Named Group
             </Button>
          </TabsContent>

          <TabsContent value="rego" className="m-0 space-y-4 animate-in slide-in-from-left-2 duration-200">
             <div className="grid grid-cols-2 gap-6" style={{ minHeight: '480px' }}>
               <div className="flex flex-col space-y-2">
                 <div className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Custom Rego Additions</div>
                 <p className="text-[11px] text-text-dim">Appended after generated rules. Can add extra <code>_any_deny</code> / <code>_any_allow</code> clauses or override <code>decision</code>.</p>
                 <textarea
                   value={current.raw_rego ?? ''}
                   onChange={e => set({ raw_rego: e.target.value })}
                   placeholder={'# optional hand-written Rego\n# _any_allow if { input.user == "admin" }'}
                   className="flex-1 font-mono text-[12px] resize-none bg-surface border border-border rounded-[4px] text-text p-3 outline-none focus:border-green"
                 />
               </div>
               <div className="flex flex-col space-y-2">
                 <div className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Compiled Module (read-only)</div>
                 <p className="text-[11px] text-text-dim">Full Rego module that OPA evaluates for every session.</p>
                 <pre className="flex-1 p-3 bg-bg border border-border rounded-[4px] font-mono text-[12px] text-blue/90 overflow-auto whitespace-pre-wrap">
                   {data.rego}
                 </pre>
               </div>
             </div>
          </TabsContent>
        </div>
      </Tabs>

      <OPARuleModal
        rule={editRule?.rule || null}
        open={!!editRule || isAddOpen}
        onClose={() => { setEditRule(null); setIsAddOpen(false) }}
        onSave={onSaveRule}
      />

      {editGroup && (
         <GroupEditModal
            name={editGroup.name}
            members={editGroup.members}
            open={!!editGroup}
            onClose={() => setEditGroup(null)}
            onSave={(members) => onSaveGroup(editGroup.name, members)}
         />
      )}
    </div>
  )
}

function GroupEditModal({ name, members, open, onClose, onSave }: { name: string, members: string[], open: boolean, onClose: () => void, onSave: (m: string[]) => void }) {
    const [draft, setDraft] = useState(members)
    return (
        <Dialog open={open} onOpenChange={onClose}>
            <DialogContent className="max-w-md bg-surface border-border text-text">
                <DialogHeader><DialogTitle>Edit Group: @{name}</DialogTitle></DialogHeader>
                <div className="py-4">
                    <TagInput label="Members" values={draft} onChange={setDraft} />
                </div>
                <DialogFooter>
                    <Button variant="ghost" onClick={onClose}>Cancel</Button>
                    <Button onClick={() => { onSave(draft); onClose() }} className="bg-green text-black font-bold">Save Group</Button>
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
          }}
          className="flex-1 bg-transparent border-none outline-none text-[11px] font-mono px-1 min-w-[60px]"
          placeholder="..."
        />
      </div>
    </div>
  )
}
