import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { fetchRedactionConfig, saveRedactionConfig } from '@/api/config'
import { Info, Plus, Trash2, Shield, EyeOff, Save } from 'lucide-react'
import { cn } from '@/lib/utils'

export function RedactionTab() {
  const queryClient = useQueryClient()
  const { data, isLoading } = useQuery({
    queryKey: ['redaction-config'],
    queryFn: fetchRedactionConfig
  })

  const [localCustom, setLocalCustom] = useState<string[]>([])
  const [isDirty, setIsLocalDirty] = useState(false)
  const [activeTab, setActiveTab] = useState<'system' | 'custom'>('system')

  // Initialize local state when data loads
  const [initialized, setInitialized] = useState(false)
  if (data && !initialized) {
    setLocalCustom(data.custom_patterns || [])
    setInitialized(true)
  }

  const mutation = useMutation({
    mutationFn: saveRedactionConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['redaction-config'] })
      setIsLocalDirty(false)
    }
  })

  const addPattern = () => {
    setLocalCustom([...localCustom, ''])
    setIsLocalDirty(true)
  }

  const updatePattern = (index: number, val: string) => {
    const next = [...localCustom]
    next[index] = val
    setLocalCustom(next)
    setIsLocalDirty(true)
  }

  const removePattern = (index: number) => {
    setLocalCustom(localCustom.filter((_, i) => i !== index))
    setIsLocalDirty(true)
  }

  if (isLoading) return <div className="p-8 text-center text-text-dim italic">Loading configuration...</div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-text mb-1 flex items-center gap-2">
            <EyeOff size={20} className="text-green" /> Secret Redaction
          </h1>
          <p className="text-text-dim text-[13px]">
            Configure patterns to mask sensitive data from terminal streams before they are stored.
          </p>
        </div>
        {activeTab === 'custom' && (
          <button
            onClick={() => mutation.mutate(localCustom)}
            disabled={!isDirty || mutation.isPending}
            className="flex items-center gap-2 h-9 px-4 bg-green text-black rounded-[4px] text-[13px] font-bold hover:bg-green/90 transition-colors disabled:opacity-50"
          >
            <Save size={14} /> {mutation.isPending ? 'Saving...' : 'Save Changes'}
          </button>
        )}
      </div>

      <div className="flex border-b border-border">
        <button
          onClick={() => setActiveTab('system')}
          className={cn(
            "px-6 py-2 text-[13px] font-medium border-b-2 transition-colors",
            activeTab === 'system' ? "border-green text-green" : "border-transparent text-text-dim hover:text-text-sub"
          )}
        >
          System Rules
        </button>
        <button
          onClick={() => setActiveTab('custom')}
          className={cn(
            "px-6 py-2 text-[13px] font-medium border-b-2 transition-colors",
            activeTab === 'custom' ? "border-green text-green" : "border-transparent text-text-dim hover:text-text-sub"
          )}
        >
          Custom Patterns
        </button>
      </div>

      {activeTab === 'system' ? (
        <div className="space-y-4">
          <div className="p-4 bg-surface border border-border rounded-md flex gap-3">
            <Info size={18} className="text-green shrink-0 mt-0.5" />
            <div className="text-[13px] text-text-sub leading-relaxed">
              These rules are built-in and active on all agents. They use high-performance regex patterns
              to identify common secrets like AWS keys, GitHub tokens, and Bearer headers.
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3">
            {data?.system_rules.map((rule, i) => (
              <div key={i} className="p-4 bg-card border border-border rounded-md group hover:border-border-mid transition-colors">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <h3 className="text-[14px] font-bold text-text-sub">{rule.name}</h3>
                    <p className="text-[12px] text-text-dim mt-0.5">{rule.description}</p>
                  </div>
                  <div className="px-2 py-0.5 bg-bg border border-border rounded text-[10px] font-mono text-text-dim uppercase">
                    Group {rule.group}
                  </div>
                </div>
                <div className="bg-bg-dark/50 p-2.5 rounded font-mono text-[12px] text-green border border-border/50 break-all">
                  {rule.regex}
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="p-4 bg-surface border border-border rounded-md flex gap-3">
            <Shield size={18} className="text-green shrink-0 mt-0.5" />
            <div className="text-[13px] text-text-sub leading-relaxed">
              Custom patterns defined here are pushed to all agents. Local patterns in
              <code className="text-green mx-1 font-mono">agent.conf</code> are still respected and merged with these.
            </div>
          </div>
          <div className="space-y-2">
            {localCustom.map((pattern, i) => (
              <div key={i} className="flex gap-2 group">
                <div className="flex-1">
                  <input
                    type="text"
                    value={pattern}
                    onChange={(e) => updatePattern(i, e.target.value)}
                    placeholder="Enter valid Go regex..."
                    className="w-full h-10 px-3 bg-card border border-border rounded-md text-[13px] font-mono text-text-sub focus:border-green outline-none transition-colors"
                  />
                </div>
                <button
                  onClick={() => removePattern(i)}
                  className="h-10 w-10 flex items-center justify-center bg-card border border-border rounded-md text-text-dim hover:text-red hover:border-red/30 transition-colors"
                  title="Remove pattern"
                >
                  <Trash2 size={16} />
                </button>
              </div>
            ))}

            <button
              onClick={addPattern}
              className="w-full py-3 border-2 border-dashed border-border rounded-md flex items-center justify-center gap-2 text-text-dim hover:border-border-mid hover:text-text-sub transition-all"
            >
              <Plus size={16} /> <span className="text-[13px] font-medium">Add custom pattern</span>
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
