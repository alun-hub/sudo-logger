import { useState, useEffect } from 'react'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'
import type { Role } from '@/types/config'

interface Props {
  role: Role | null
  open: boolean
  onClose: () => void
  onSave: (role: Role) => void
}

const ALL_PERMS = [
  'sessions:list_all',
  'sessions:list_own',
  'sessions:read',
  'sessions:delete',
  'policy:read',
  'policy:write',
  'config:read',
  'config:write',
  'users:read',
  'users:write',
  'approvals:write',
]

export function RoleModal({ role, open, onClose, onSave }: Props) {
  const [name, setName] = useState('')
  const [permissions, setPermissions] = useState<string[]>([])

  useEffect(() => {
    if (role) {
      setName(role.name)
      setPermissions(role.permissions)
    } else {
      setName('')
      setPermissions([])
    }
  }, [role, open])

  const save = () => {
    onSave({ name, permissions })
    onClose()
  }

  const togglePerm = (p: string) => {
    if (permissions.includes(p)) setPermissions(permissions.filter(x => x !== p))
    else setPermissions([...permissions, p])
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-md bg-surface border-border text-text">
        <DialogHeader>
          <DialogTitle>{role ? 'Edit Role' : 'Create Role'}</DialogTitle>
        </DialogHeader>

        <div className="space-y-6 py-4">
          <div className="space-y-1.5">
            <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Role Name</label>
            <Input
              value={name}
              onChange={e => setName(e.target.value)}
              disabled={!!role}
              placeholder="operator"
              className="bg-card border-border h-9 font-mono uppercase"
            />
          </div>

          <div className="space-y-3">
             <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Permissions</label>
             <div className="grid grid-cols-2 gap-2">
                {ALL_PERMS.map(p => {
                  const isActive = permissions.includes(p)
                  return (
                    <button
                      key={p}
                      onClick={() => togglePerm(p)}
                      className={cn(
                        "text-left px-2 py-1 rounded-[3px] border text-[11px] font-mono transition-colors",
                        isActive
                          ? "bg-blue/10 border-blue/40 text-blue font-bold"
                          : "bg-card border-border text-text-dim hover:border-border-mid"
                      )}
                    >
                      {p.replace(':', ': ')}
                    </button>
                  )
                })}
             </div>
          </div>
        </div>

        <DialogFooter className="mt-4 border-t border-border pt-4">
          <Button variant="ghost" onClick={onClose} className="h-9 px-4 text-text-dim hover:text-text hover:bg-card-hover">Cancel</Button>
          <Button onClick={save} className="h-9 px-6 bg-green hover:bg-green/90 text-black font-bold">Save Role</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
