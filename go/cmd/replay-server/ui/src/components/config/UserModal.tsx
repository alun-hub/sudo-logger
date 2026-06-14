import { useState, useEffect } from 'react'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import type { UserInfo, Role } from '@/types/config'

interface Props {
  user: UserInfo | null
  roles: Role[]
  open: boolean
  onClose: () => void
  onSave: (user: any) => void
}

export function UserModal({ user, roles, open, onClose, onSave }: Props) {
  const [username, setUsername] = useState('')
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('viewer')

  useEffect(() => {
    if (user) {
      setUsername(user.username)
      setFullName(user.full_name || '')
      setEmail(user.email || '')
      setRole(user.role)
    } else {
      setUsername('')
      setFullName('')
      setEmail('')
      setRole('viewer')
    }
    setPassword('')
  }, [user, open])

  const save = () => {
    onSave({
      username,
      full_name: fullName,
      email,
      password_hash: password || undefined,
      role,
      source: 'local'
    })
    onClose()
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-md bg-surface border-border text-text">
        <DialogHeader>
          <DialogTitle>{user ? 'Edit User' : 'Create Local User'}</DialogTitle>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="space-y-1.5">
            <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Username</label>
            <Input
              value={username}
              onChange={e => setUsername(e.target.value)}
              disabled={!!user}
              placeholder="alice"
              className="bg-card border-border h-9 font-mono"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
             <div className="space-y-1.5">
                <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Full Name</label>
                <Input
                  value={fullName}
                  onChange={e => setFullName(e.target.value)}
                  placeholder="Alice Smith"
                  className="bg-card border-border h-9"
                />
             </div>
             <div className="space-y-1.5">
                <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Role</label>
                <select
                  value={role}
                  onChange={e => setRole(e.target.value)}
                  className="w-full h-9 bg-card border border-border rounded-[5px] px-2 text-[13px] outline-none focus:border-green"
                >
                  {roles.map(r => <option key={r.name} value={r.name}>{r.name.toUpperCase()}</option>)}
                </select>
             </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Email Address</label>
            <Input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="alice@example.com"
              className="bg-card border-border h-9"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-[11px] font-bold text-text-dim uppercase tracking-wider">
              {user ? 'New Password (optional)' : 'Initial Password'}
            </label>
            <Input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              autoComplete="new-password"
              className="bg-card border-border h-9 font-mono"
            />
          </div>
        </div>

        <DialogFooter className="mt-4 border-t border-border pt-4">
          <Button variant="ghost" onClick={onClose} className="h-9 px-4 text-text-dim hover:text-text hover:bg-card-hover">Cancel</Button>
          <Button onClick={save} className="h-9 px-6 bg-green hover:bg-green/90 text-black font-bold">Save User</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
