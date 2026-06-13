import { useState, useEffect } from 'react'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from './dialog'
import { Button } from './button'

interface ConfirmDialogProps {
  open: boolean
  title?: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
  danger?: boolean
  onConfirm: () => void
  onCancel: () => void
}

export function ConfirmDialog({
  open, title = 'Confirm', message, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger, onConfirm, onCancel,
}: ConfirmDialogProps) {
  return (
    <Dialog open={open} onOpenChange={open => !open && onCancel()}>
      <DialogContent className="max-w-sm bg-surface border-border text-text">
        <DialogHeader>
          <DialogTitle className="text-[15px]">{title}</DialogTitle>
        </DialogHeader>
        <p className="text-[13px] text-text-sub py-2">{message}</p>
        <DialogFooter className="border-t border-border pt-4">
          <Button variant="ghost" onClick={onCancel}
            className="h-9 px-4 text-text-dim hover:text-text hover:bg-card-hover">
            {cancelLabel}
          </Button>
          <Button onClick={onConfirm}
            className={`h-9 px-6 font-bold ${danger
              ? 'bg-red hover:bg-red/90 text-white'
              : 'bg-green hover:bg-green/90 text-black'}`}>
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

interface InputDialogProps {
  open: boolean
  title?: string
  message: string
  placeholder?: string
  defaultValue?: string
  confirmLabel?: string
  optional?: boolean
  onConfirm: (value: string) => void
  onCancel: () => void
}

export function InputDialog({
  open, title = 'Input', message, placeholder = '', defaultValue = '',
  confirmLabel = 'OK', optional, onConfirm, onCancel,
}: InputDialogProps) {
  const [value, setValue] = useState(defaultValue)

  useEffect(() => {
    if (open) setValue(defaultValue)
  }, [open, defaultValue])

  const submit = () => {
    if (!optional && !value.trim()) return
    onConfirm(value)
  }

  return (
    <Dialog open={open} onOpenChange={open => !open && onCancel()}>
      <DialogContent className="max-w-sm bg-surface border-border text-text">
        <DialogHeader>
          <DialogTitle className="text-[15px]">{title}</DialogTitle>
        </DialogHeader>
        <div className="py-2 space-y-3">
          <p className="text-[13px] text-text-sub">{message}</p>
          <input
            value={value}
            onChange={e => setValue(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && submit()}
            placeholder={placeholder}
            autoFocus
            className="w-full h-9 bg-card border border-border rounded-[5px] px-3 text-[13px] font-mono outline-none focus:border-green transition-colors"
          />
        </div>
        <DialogFooter className="border-t border-border pt-4">
          <Button variant="ghost" onClick={onCancel}
            className="h-9 px-4 text-text-dim hover:text-text hover:bg-card-hover">
            Cancel
          </Button>
          <Button onClick={submit}
            className="h-9 px-6 bg-green hover:bg-green/90 text-black font-bold">
            {confirmLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
