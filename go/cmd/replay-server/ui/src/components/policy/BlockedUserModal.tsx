import { useState, useEffect } from 'react'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { X } from 'lucide-react'
import type { BlockedUser } from '@/api/policy'

interface Props {
  user: BlockedUser | null
  open: boolean
  onClose: () => void
  onSave: (user: BlockedUser) => void
}

export function BlockedUserModal({ user, open, onClose, onSave }: Props) {
  const [draft, setDraft] = useState<BlockedUser>(emptyUser())

  useEffect(() => {
    if (user) setDraft(JSON.parse(JSON.stringify(user)))
    else setDraft(emptyUser())
  }, [user, open])

  const save = () => {
    onSave(draft)
    onClose()
  }

  const addHost = (h: string) => {
    const val = h.trim()
    if (!val || draft.hosts.includes(val)) return
    setDraft({ ...draft, hosts: [...draft.hosts, val] })
  }

  const removeHost = (h: string) => setDraft({ ...draft, hosts: draft.hosts.filter(x => x !== h) })

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-md bg-surface border-border text-text">
        <DialogHeader>
          <DialogTitle>{user ? 'Edit Block' : 'Block User'}</DialogTitle>
        </DialogHeader>

        <div className="space-y-6 py-4">
          <div className="space-y-1.5">
            <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Username</label>
            <Input
              value={draft.username}
              onChange={e => setDraft({ ...draft, username: e.target.value })}
              placeholder="alice"
              className="bg-card border-border h-10 font-mono"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Reason (internal note)</label>
            <Input
              value={draft.reason}
              onChange={e => setDraft({ ...draft, reason: e.target.value })}
              placeholder="Ticket SEC-123"
              className="bg-card border-border h-10"
            />
          </div>

          <div className="space-y-3">
             <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Hosts (empty = all hosts)</label>
             <div className="min-h-10 p-1 rounded-[5px] border border-border bg-card flex flex-wrap gap-1 items-center">
                {draft.hosts.map(h => (
                  <span key={h} className="bg-surface border border-border px-2 py-0.5 rounded-[3px] text-[12px] font-mono text-red flex items-center gap-1.5">
                    {h}
                    <button onClick={() => removeHost(h)} className="text-text-dim hover:text-red transition-colors"><X size={12} /></button>
                  </span>
                ))}
                <input
                  onKeyDown={e => {
                    if (e.key === 'Enter' || e.key === ',') {
                      e.preventDefault()
                      addHost((e.target as HTMLInputElement).value)
                      ;(e.target as HTMLInputElement).value = ''
                    }
                  }}
                  className="flex-1 bg-transparent border-none outline-none text-[12px] font-mono px-2 min-w-[120px]"
                  placeholder="type host and press Enter..."
                />
             </div>
             <p className="text-[11px] text-text-dim italic">Leave empty to block the user across the entire fleet.</p>
          </div>
        </div>

        <DialogFooter className="mt-4 border-t border-border pt-4">
          <Button variant="ghost" onClick={onClose} className="h-9 px-4 text-text-dim hover:text-text hover:bg-card-hover">Cancel</Button>
          <Button onClick={save} className="h-9 px-6 bg-red hover:bg-red/90 text-white font-bold">Save Block</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function emptyUser(): BlockedUser {
  return { username: '', hosts: [], reason: '' }
}
