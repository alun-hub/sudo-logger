import { useState, type ChangeEvent, type KeyboardEvent } from 'react'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'

interface Props {
  label: string
  values: string[]
  onChange: (values: string[]) => void
}

export function TagList({ label, values, onChange }: Props) {
  const [draft, setDraft] = useState('')

  const add = () => {
    const v = draft.trim()
    if (v && !values.includes(v)) onChange([...values, v])
    setDraft('')
  }

  return (
    <div className="space-y-2">
      <p className="text-sm font-medium text-zinc-700 dark:text-zinc-300">{label}</p>
      <div className="flex gap-2">
        <Input
          value={draft}
          onChange={(e: ChangeEvent<HTMLInputElement>) => setDraft(e.target.value)}
          onKeyDown={(e: KeyboardEvent<HTMLInputElement>) => e.key === 'Enter' && add()}
          placeholder="username"
          className="h-7 text-sm"
        />
        <Button size="sm" onClick={add} variant="outline" className="h-7">Add</Button>
      </div>
      <div className="flex flex-wrap gap-1">
        {values.map(v => (
          <span
            key={v}
            className="flex items-center gap-1 bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 text-xs px-2 py-0.5 rounded-full"
          >
            {v}
            <button
              onClick={() => onChange(values.filter(x => x !== v))}
              className="text-zinc-400 hover:text-zinc-700"
            >×</button>
          </span>
        ))}
      </div>
    </div>
  )
}
