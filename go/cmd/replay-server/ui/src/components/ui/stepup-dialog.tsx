import { useState, useEffect } from 'react'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from './dialog'
import { Button } from './button'
import { submitStepUp } from '@/api/stepup'

interface StepUpDialogProps {
  open: boolean
  onVerified: () => void
  onCancel: () => void
}

/**
 * StepUpDialog re-collects the current user's password for a sensitive
 * action (sudoers/sandbox push) that requires a recent step-up
 * re-authentication (local-auth mode only — see requireStepUp in
 * go/cmd/replay-server/rbac.go and the OIDC-mode redirect handled by the
 * caller instead of this dialog).
 */
export function StepUpDialog({ open, onVerified, onCancel }: StepUpDialogProps) {
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [pending, setPending] = useState(false)

  useEffect(() => {
    if (open) { setPassword(''); setError(''); setPending(false) }
  }, [open])

  const submit = async () => {
    if (!password || pending) return
    setPending(true)
    setError('')
    try {
      await submitStepUp(password)
      onVerified()
    } catch {
      setError('Incorrect password')
    } finally {
      setPending(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={open => !open && onCancel()}>
      <DialogContent className="max-w-sm bg-surface border-border text-text">
        <DialogHeader>
          <DialogTitle className="text-[15px]">Confirm it's you</DialogTitle>
        </DialogHeader>
        <div className="py-2 space-y-3">
          <p className="text-[13px] text-text-sub">
            This action requires re-entering your password.
          </p>
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && submit()}
            placeholder="Password"
            autoFocus
            className="w-full h-9 bg-card border border-border rounded-[5px] px-3 text-[13px] outline-none focus:border-green transition-colors"
          />
          {error && <p className="text-[12px] text-red">{error}</p>}
        </div>
        <DialogFooter className="border-t border-border pt-4">
          <Button variant="ghost" onClick={onCancel}
            className="h-9 px-4 text-text-dim hover:text-text hover:bg-card-hover">
            Cancel
          </Button>
          <Button onClick={submit} disabled={!password || pending}
            className="h-9 px-6 bg-green hover:bg-green/90 text-black font-bold disabled:opacity-50">
            {pending ? 'Verifying…' : 'Confirm'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
