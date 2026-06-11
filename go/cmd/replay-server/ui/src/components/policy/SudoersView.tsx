import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  fetchSudoersHosts,
  fetchSudoersConfig,
  saveSudoersConfig,
  deleteSudoersOverride,
  fetchSudoersSnapshots,
} from '@/api/sudoers'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { Shield, Clock, AlertTriangle, CheckCircle2, Save, Trash2, RotateCcw } from 'lucide-react'
import { fmtDate } from '@/lib/date'

export function SudoersView() {
  const [selectedHost, setSelectedHost] = useState<string>('_default')
  const { data: hosts, isPending } = useQuery({
    queryKey: ['sudoers-hosts'],
    queryFn: fetchSudoersHosts,
    refetchInterval: 30_000
  })

  if (isPending) return <div className="p-8 text-text-dim font-mono text-[13px]">Loading hosts…</div>

  const sortedHosts = hosts ? ['_default', ...hosts.map(h => h.name).filter(h => h !== '_default')] : ['_default']

  return (
    <div className="flex h-full overflow-hidden">
      {/* Host Sidebar */}
      <div className="w-[240px] border-r border-border bg-surface flex flex-col shrink-0">
        <div className="p-3 border-b border-border">
          <h3 className="text-[11px] font-bold text-text-dim uppercase tracking-wider">Monitored Hosts</h3>
        </div>
        <div className="flex-1 overflow-y-auto">
          {sortedHosts.map(name => {
            const h = hosts?.find(x => x.name === name)
            const isActive = selectedHost === name
            const isDefault = name === '_default'

            return (
              <button
                key={name}
                onClick={() => setSelectedHost(name)}
                className={cn(
                  "w-full text-left px-3 py-2.5 border-b border-border flex items-center justify-between transition-colors group",
                  isActive ? "bg-card-active" : "hover:bg-card-hover"
                )}
              >
                <div className="flex flex-col gap-0.5 overflow-hidden">
                  <span className={cn(
                    "text-[13px] font-mono truncate",
                    isActive ? "text-green font-bold" : "text-text-sub group-hover:text-text"
                  )}>
                    {isDefault ? 'Global Default' : name}
                  </span>
                  <div className="flex items-center gap-1.5">
                    {isDefault ? (
                       <span className="text-[10px] text-text-dim uppercase">Base Template</span>
                    ) : (
                      <>
                        <span className={cn(
                          "text-[9px] px-1 rounded-[2px] border font-bold uppercase",
                          h?.isOverride ? "border-blue/30 text-blue bg-blue/5" : "border-border text-text-dim"
                        )}>
                          {h?.isOverride ? 'Modified' : 'Default'}
                        </span>
                        {h?.inSync ? (
                          <CheckCircle2 size={10} className="text-green" />
                        ) : (
                          <Clock size={10} className="text-amber" />
                        )}
                      </>
                    )}
                  </div>
                </div>
                {h?.error && <AlertTriangle size={14} className="text-red shrink-0" />}
              </button>
            )
          })}
        </div>
      </div>

      {/* Editor Area */}
      <div className="flex-1 flex flex-col bg-bg overflow-hidden">
        <EditorPanel host={selectedHost} />
      </div>
    </div>
  )
}

function EditorPanel({ host }: { host: string }) {
  const qc = useQueryClient()
  const { data: config, isPending: p1 } = useQuery({
    queryKey: ['sudoers-config', host],
    queryFn: () => fetchSudoersConfig(host)
  })
  const { data: snaps, isPending: p2 }  = useQuery({
    queryKey: ['sudoers-snapshots', host],
    queryFn: () => fetchSudoersSnapshots(host),
    enabled: host !== '_default'
  })

  const [content, setContent] = useState<string | null>(null)

  const save = useMutation({
    mutationFn: (c: string) => saveSudoersConfig(host, c),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sudoers-config', host] })
      qc.invalidateQueries({ queryKey: ['sudoers-hosts'] })
      setContent(null)
    }
  })

  const remove = useMutation({
    mutationFn: () => deleteSudoersOverride(host),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sudoers-config', host] })
      qc.invalidateQueries({ queryKey: ['sudoers-hosts'] })
      setContent(null)
    }
  })

  if (p1 || (host !== '_default' && p2)) {
    return <div className="p-8 text-text-dim font-mono text-[13px]">Loading configuration…</div>
  }

  const currentContent = content ?? config?.content ?? ''
  const isDirty = content !== null && content !== config?.content
  const isGlobal = host === '_default'

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="h-[52px] border-b border-border bg-surface px-4 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <Shield size={18} className={isGlobal ? "text-blue" : "text-green"} />
          <div className="flex flex-col">
            <h2 className="text-[14px] font-bold text-text">
              {isGlobal ? 'Global sudoers Template' : `Host Override: ${host}`}
            </h2>
            <p className="text-[11px] text-text-dim">
              {isGlobal
                ? 'Base policy inherited by all hosts without local overrides.'
                : (config?.is_override ? 'Custom policy active for this host.' : 'Inheriting global default.')
              }
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {isDirty && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setContent(null)}
              className="h-8 text-text-dim hover:text-text"
            >
              <RotateCcw size={14} className="mr-1.5" /> Discard
            </Button>
          )}
          {!isGlobal && config?.is_override && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => confirm(`Revert ${host} to global default?`) && remove.mutate()}
              className="h-8 text-text-dim hover:text-red"
            >
              <Trash2 size={14} className="mr-1.5" /> Revert
            </Button>
          )}
          <Button
            size="sm"
            disabled={!isDirty || save.isPending}
            onClick={() => save.mutate(currentContent)}
            className="h-8 bg-green hover:bg-green/90 text-black font-bold px-4 rounded-[4px]"
          >
            <Save size={14} className="mr-1.5" /> {save.isPending ? 'Saving...' : 'Save Changes'}
          </Button>
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* Editor */}
        <div className="flex-1 flex flex-col border-r border-border">
          <textarea
            value={currentContent}
            onChange={e => setContent(e.target.value)}
            spellCheck={false}
            className="flex-1 bg-[#050508] text-[#d4daf0] font-mono text-[13px] p-6 outline-none resize-none leading-relaxed"
            placeholder="# Sudoers policy goes here..."
          />
        </div>

        {/* Snapshots Sidebar */}
        {!isGlobal && (
          <div className="w-[300px] flex flex-col bg-surface overflow-hidden shrink-0">
            <div className="p-3 border-b border-border bg-card/30">
               <h3 className="text-[11px] font-bold text-text-dim uppercase tracking-wider flex items-center gap-2">
                 <Clock size={12} /> Active Snapshots
               </h3>
            </div>
            <div className="flex-1 overflow-y-auto p-2 space-y-2">
              {snaps?.snapshots.map(s => (
                <div key={s.sha256} className="p-2.5 rounded-[4px] border border-border bg-card hover:border-border-mid transition-colors">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[12px] font-bold text-text-sub">{fmtDate(s.uploaded_at)}</span>
                    <span className="text-[9px] font-mono text-text-dim">{s.sha256.substring(0, 8)}</span>
                  </div>
                  <div className="text-[11px] text-text-dim truncate font-mono bg-bg/50 p-1 rounded">
                    {s.content.split('\n').filter(l => l && !l.startsWith('#')).slice(0, 3).join(', ')}...
                  </div>
                </div>
              ))}
              {snaps?.snapshots.length === 0 && (
                <div className="p-4 text-center text-[12px] text-text-dim italic">
                  No snapshots recorded yet. Ensure sudo-logger-agent is running.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
