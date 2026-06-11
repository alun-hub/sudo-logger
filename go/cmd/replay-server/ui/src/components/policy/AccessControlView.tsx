import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  fetchBlockedPolicy, saveBlockedPolicy,
  fetchWhitelistPolicy, saveWhitelistPolicy,
  type BlockedUser,
} from '@/api/opa'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Trash2, Plus, Edit2, ShieldAlert, CheckCircle2, MessageSquare, Save } from 'lucide-react'
import { BlockedUserModal } from './BlockedUserModal'
import { fmtDate } from '@/lib/date'

export function AccessControlView() {
  const qc = useQueryClient()
  const { data: blocked, isPending: p1 } = useQuery({ queryKey: ['blocked-policy'], queryFn: fetchBlockedPolicy })
  const { data: white,   isPending: p2 } = useQuery({ queryKey: ['whitelist-policy'], queryFn: fetchWhitelistPolicy })

  const [editBlock, setEditBlock] = useState<BlockedUser | null>(null)
  const [isAddBlockOpen, setIsAddBlockOpen] = useState(false)
  const [msgDraft, setMsgDraft] = useState<string | null>(null)

  const mutBlock = useMutation({
    mutationFn: saveBlockedPolicy,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['blocked-policy'] }),
  })
  const mutWhite = useMutation({
    mutationFn: saveWhitelistPolicy,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['whitelist-policy'] }),
  })

  if (p1 || p2 || !blocked || !white) return <div className="p-8 text-text-dim font-mono text-[13px]">Loading access control…</div>

  const onSaveBlock = (user: BlockedUser) => {
    const isNew = !blocked.users.find(u => u.username === user.username)
    let next: BlockedUser[]
    if (isNew) {
      next = [...blocked.users, { ...user, blocked_at: Math.floor(Date.now() / 1000) }]
    } else {
      next = blocked.users.map(u => u.username === user.username ? user : u)
    }
    mutBlock.mutate({ ...blocked, users: next })
  }

  const deleteBlock = (username: string) => {
    if (!confirm(`Unblock user ${username}?`)) return
    mutBlock.mutate({ ...blocked, users: blocked.users.filter(u => u.username !== username) })
  }

  const saveMsg = () => {
    if (msgDraft === null) return
    mutBlock.mutate({ ...blocked, message: msgDraft })
    setMsgDraft(null)
  }

  const addWhite = () => {
    const name = prompt('Enter username to whitelist:')
    if (!name) return
    if (white.users.includes(name)) return
    mutWhite.mutate({ users: [...white.users, name] })
  }

  const deleteWhite = (name: string) => {
    if (!confirm(`Remove ${name} from whitelist?`)) return
    mutWhite.mutate({ users: white.users.filter(u => u !== name) })
  }

  return (
    <div className="p-6 space-y-12 max-w-6xl mx-auto animate-in fade-in duration-200">
      {/* Block Message */}
      <section className="space-y-6">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
            <MessageSquare size={18} className="text-amber" /> Block Message
          </h2>
          <Button
            size="sm"
            disabled={msgDraft === null || mutBlock.isPending}
            onClick={saveMsg}
            className="h-8 bg-green hover:bg-green/90 text-black font-bold px-4 rounded-[4px]"
          >
            <Save size={14} className="mr-1.5" /> Save Message
          </Button>
        </div>
        <div className="space-y-2">
          <p className="text-[12px] text-text-dim">This message is shown to blocked users when they attempt to run sudo.</p>
          <textarea
            value={msgDraft ?? blocked.message}
            onChange={e => setMsgDraft(e.target.value)}
            className="w-full bg-[#050508] text-text font-mono text-[13px] p-4 border border-border rounded-[5px] outline-none focus:border-green min-h-[80px] resize-none"
            placeholder="Your sudo access has been temporarily suspended..."
          />
        </div>
      </section>

      {/* Blocked Users */}
      <section className="space-y-6">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
            <ShieldAlert size={18} className="text-red" /> Blocked Users
          </h2>
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
                 <TableHead className="text-text-dim h-9">Username</TableHead>
                 <TableHead className="text-text-dim h-9">Hosts</TableHead>
                 <TableHead className="text-text-dim h-9">Reason</TableHead>
                 <TableHead className="text-text-dim h-9">Blocked at</TableHead>
                 <TableHead className="w-24 h-9"></TableHead>
               </TableRow>
             </TableHeader>
             <TableBody>
               {blocked.users.length === 0 ? (
                 <TableRow><TableCell colSpan={5} className="text-center py-12 text-text-dim italic">No users are currently blocked.</TableCell></TableRow>
               ) : blocked.users.map(u => (
                 <TableRow key={u.username} className="hover:bg-card-hover border-border group">
                   <TableCell className="font-mono font-bold text-red">{u.username}</TableCell>
                   <TableCell className="font-mono text-[12px] text-text-sub">
                     {u.hosts.length === 0 ? <span className="text-text-dim">All Hosts</span> : u.hosts.join(', ')}
                   </TableCell>
                   <TableCell className="text-text-sub">{u.reason}</TableCell>
                   <TableCell className="text-text-dim font-mono text-[11px] whitespace-nowrap">
                     {u.blocked_at ? fmtDate(u.blocked_at) : '—'}
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
      </section>

      {/* Whitelisted Users */}
      <section className="space-y-6">
        <div className="flex items-center justify-between border-b border-border pb-2">
          <h2 className="text-[16px] font-semibold text-text flex items-center gap-2">
            <CheckCircle2 size={18} className="text-green" /> Whitelisted Users
            <span className="text-[11px] text-text-dim font-normal ml-2 uppercase tracking-wider">— bypass JIT approval</span>
          </h2>
          <Button
            onClick={addWhite}
            size="sm" variant="outline" className="h-8 border-border hover:bg-card-hover text-text-sub"
          >
            <Plus size={14} className="mr-1" /> Add User
          </Button>
        </div>
        <div className="rounded-[5px] border border-border bg-card overflow-hidden max-w-2xl">
           <Table className="text-[13px]">
             <TableHeader className="bg-surface">
               <TableRow className="hover:bg-transparent border-border">
                 <TableHead className="text-text-dim h-9">Username</TableHead>
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
      </section>

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
