import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Routes, Route, NavLink, Navigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Plus, Edit2, Trash2, Shield, Users, Code, Search, Server } from 'lucide-react'
import { cn } from '@/lib/utils'
import {
  fetchRules, saveRules,
  fetchBlockedUsers, setBlockedUsers,
  fetchWhitelistedUsers, setWhitelistedUsers,
  fetchCompiledRego,
  type Rule,
  type BlockedUser,
} from '@/api/policy'
import { RuleModal } from './RuleModal'
import { BlockedUserModal } from './BlockedUserModal'
import { SudoersView } from './SudoersView'

export function PolicyEditor() {
  return (
    <div className="flex flex-col h-[calc(100vh-[44px])] bg-bg text-text-sub overflow-hidden">
      <div className="px-4 border-b border-border bg-surface shrink-0">
        <nav className="h-[44px] flex items-center gap-1">
          <SubTab to="rules" label="Risk Rules" icon={<Shield size={14} />} />
          <SubTab to="sudoers" label="Sudoers" icon={<Server size={14} />} />
          <SubTab to="users" label="User Groups" icon={<Users size={14} />} />
          <SubTab to="opa" label="Compiled Rego" icon={<Code size={14} />} />
        </nav>
      </div>

      <div className="flex-1 overflow-y-auto">
        <Routes>
          <Route path="rules"   element={<div className="p-6 animate-in fade-in duration-200"><RulesPanel /></div>} />
          <Route path="sudoers" element={<SudoersView />} />
          <Route path="users"   element={<div className="p-6 animate-in fade-in duration-200"><UserGroupsPanel /></div>} />
          <Route path="opa"     element={<div className="p-6 animate-in fade-in duration-200"><RegoPanel /></div>} />
          <Route path=""        element={<Navigate to="rules" replace />} />
        </Routes>
      </div>
    </div>
  )
}

function SubTab({ to, label, icon }: { to: string, label: string, icon: React.ReactNode }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) => cn(
        "h-full flex items-center gap-2 px-4 text-[13px] font-medium transition-all border-b-2",
        isActive
          ? "border-green text-green"
          : "border-transparent text-text-dim hover:text-text-sub hover:bg-card-hover"
      )}
    >
      {icon} {label}
    </NavLink>
  )
}

function RulesPanel() {
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

function UserGroupsPanel() {
  const qc = useQueryClient()
  const { data: blocked } = useQuery({ queryKey: ['blocked-users'], queryFn: fetchBlockedUsers })
  const { data: white   } = useQuery({ queryKey: ['whitelisted-users'], queryFn: fetchWhitelistedUsers })

  const [editBlock, setEditBlock] = useState<BlockedUser | null>(null)
  const [isAddBlockOpen, setIsAddBlockOpen] = useState(false)

  const mutBlock = useMutation({
    mutationFn: setBlockedUsers,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['blocked-users'] }),
  })
  const mutWhite = useMutation({
    mutationFn: setWhitelistedUsers,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['whitelisted-users'] }),
  })

  if (!blocked || !white) return null

  const onSaveBlock = (user: BlockedUser) => {
    const isNew = !blocked.users.find(u => u.username === user.username)
    let next: BlockedUser[]
    if (isNew) {
      next = [...blocked.users, user]
    } else {
      next = blocked.users.map(u => u.username === user.username ? user : u)
    }
    mutBlock.mutate(next)
  }

  const deleteBlock = (username: string) => {
    if (!confirm(`Unblock user ${username}?`)) return
    mutBlock.mutate(blocked.users.filter(u => u.username !== username))
  }

  const addWhite = () => {
    const name = prompt('Enter username to whitelist:')
    if (!name) return
    if (white.users.includes(name)) return
    mutWhite.mutate([...white.users, name])
  }

  const deleteWhite = (name: string) => {
    if (!confirm(`Remove ${name} from whitelist?`)) return
    mutWhite.mutate(white.users.filter(u => u !== name))
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-[15px] font-semibold text-text">Blocked Users</h2>
          <Button
            onClick={() => setIsAddBlockOpen(true)}
            size="sm" variant="outline" className="h-8 border-border hover:bg-card-hover text-text-sub"
          >
            <Plus size={14} className="mr-1" /> Add Block
          </Button>
        </div>
        <div className="rounded-[5px] border border-border bg-card overflow-hidden">
           <Table className="text-[13px]">
             <TableHeader className="bg-surface">
               <TableRow className="hover:bg-transparent border-border">
                 <TableHead className="text-text-dim h-9">User</TableHead>
                 <TableHead className="text-text-dim h-9">Reason / Hosts</TableHead>
                 <TableHead className="w-24 h-9"></TableHead>
               </TableRow>
             </TableHeader>
             <TableBody>
               {blocked.users.length === 0 ? (
                 <TableRow><TableCell colSpan={3} className="text-center py-8 text-text-dim italic">No users blocked.</TableCell></TableRow>
               ) : blocked.users.map(u => (
                 <TableRow key={u.username} className="hover:bg-card-hover border-border group">
                   <TableCell className="font-mono font-bold text-red">{u.username}</TableCell>
                   <TableCell>
                     <div className="text-text-sub">{u.reason}</div>
                     <div className="text-[11px] text-text-dim">Hosts: {u.hosts.length === 0 ? 'All' : u.hosts.join(', ')}</div>
                   </TableCell>
                   <TableCell>
                     <div className="flex justify-end gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                        <button onClick={() => setEditBlock(u)} className="p-1.5 text-text-dim hover:text-white"><Edit2 size={14} /></button>
                        <button onClick={() => deleteBlock(u.username)} className="p-1.5 text-text-dim hover:text-red"><Trash2 size={14} /></button>
                     </div>
                   </TableCell>
                 </TableRow>
               ))}
             </TableBody>
           </Table>
        </div>
      </div>

      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-[15px] font-semibold text-text">Whitelisted Users</h2>
          <Button
            onClick={addWhite}
            size="sm" variant="outline" className="h-8 border-border hover:bg-card-hover text-text-sub"
          >
            <Plus size={14} className="mr-1" /> Add White
          </Button>
        </div>
        <div className="rounded-[5px] border border-border bg-card overflow-hidden">
           <Table className="text-[13px]">
             <TableHeader className="bg-surface">
               <TableRow className="hover:bg-transparent border-border">
                 <TableHead className="text-text-dim h-9">User</TableHead>
                 <TableHead className="w-16 h-9"></TableHead>
               </TableRow>
             </TableHeader>
             <TableBody>
                {white.users.length === 0 ? (
                  <TableRow><TableCell colSpan={2} className="text-center py-8 text-text-dim italic">No users whitelisted.</TableCell></TableRow>
                ) : white.users.map(u => (
                  <TableRow key={u} className="hover:bg-card-hover border-border group">
                    <TableCell className="font-mono font-bold text-green">{u}</TableCell>
                    <TableCell>
                      <button onClick={() => deleteWhite(u)} className="p-1.5 text-text-dim hover:text-red opacity-0 group-hover:opacity-100 transition-opacity"><Trash2 size={14} /></button>
                    </TableCell>
                  </TableRow>
                ))}
             </TableBody>
           </Table>
        </div>
      </div>

      <BlockedUserModal
        user={editBlock}
        open={!!editBlock}
        onClose={() => setEditBlock(null)}
        onSave={onSaveBlock}
      />
      <BlockedUserModal
        user={null}
        open={isAddBlockOpen}
        onClose={() => setIsAddBlockOpen(false)}
        onSave={onSaveBlock}
      />
    </div>
  )
}

function RegoPanel() {
  const { data, isPending } = useQuery({ queryKey: ['compiled-rego'], queryFn: fetchCompiledRego })

  if (isPending) return <div className="text-text-dim font-mono text-[13px]">Compiling policy…</div>
  if (!data) return null

  return (
    <div className="space-y-4 text-left">
      <div className="flex items-center justify-between">
        <h2 className="text-[15px] font-semibold text-text">Compiled OPA Rego</h2>
        <div className="text-[11px] text-text-dim italic">Read-only generated policy</div>
      </div>
      <pre className="p-4 bg-[#050508] border border-border rounded-[5px] font-mono text-[12px] text-blue leading-relaxed overflow-x-auto whitespace-pre-wrap">
        {data.rego}
      </pre>
    </div>
  )
}
