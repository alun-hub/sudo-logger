import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchOPAPolicy, saveOPAPolicy, type OPAMatchRule, type OPAPolicy } from '@/api/opa'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Plus, Edit2, Trash2, ShieldCheck, Users, Code, Save, RotateCcw } from 'lucide-react'
import { cn } from '@/lib/utils'

export function OPAPolicyView() {
  const qc = useQueryClient()
  const { data, isPending } = useQuery({ queryKey: ['opa-policy'], queryFn: fetchOPAPolicy })
  const [draft, setDraft] = useState<OPAPolicy | null>(null)

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
                           </div>
                        </TableCell>
                        <TableCell className="text-text-dim italic">{r.comment || '—'}</TableCell>
                        <TableCell>
                           <div className="flex justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                              <button className="p-1.5 text-text-dim hover:text-white"><Edit2 size={14} /></button>
                              <button className="p-1.5 text-text-dim hover:text-red"><Trash2 size={14} /></button>
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
             <Button size="sm" variant="outline" className="h-9 border-border text-text-sub"><Plus size={16} className="mr-1" /> Add Policy Rule</Button>
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
                              <button className="p-1.5 text-text-dim hover:text-white"><Edit2 size={14} /></button>
                              <button className="p-1.5 text-text-dim hover:text-red"><Trash2 size={14} /></button>
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
             <Button size="sm" variant="outline" className="h-9 border-border text-text-sub"><Plus size={16} className="mr-1" /> Add Named Group</Button>
          </TabsContent>

          <TabsContent value="rego" className="m-0 space-y-4 animate-in slide-in-from-left-2 duration-200">
             <div className="flex items-center justify-between">
                <h3 className="text-[14px] font-semibold text-text flex items-center gap-2"><Code size={16} className="text-blue" /> Generated Rego Source</h3>
                <span className="text-[11px] text-text-dim uppercase tracking-wider">Read-only compiled output</span>
             </div>
             <pre className="p-6 bg-[#050508] border border-border rounded-[5px] font-mono text-[12px] text-blue/90 leading-relaxed overflow-x-auto whitespace-pre-wrap min-h-[400px]">
                {data.rego}
             </pre>
          </TabsContent>
        </div>
      </Tabs>
    </div>
  )
}

function StatCard({ label, value, color }: { label: string; value: string | number; color?: string }) {
  return (
    <div className="bg-card border border-border p-3 rounded-[5px] shadow-sm">
      <div className="text-[11px] text-text-dim uppercase tracking-wider font-medium mb-1">{label}</div>
      <div className={cn("text-xl font-mono font-bold tabular-nums", color || "text-text")}>{value}</div>
    </div>
  )
}
