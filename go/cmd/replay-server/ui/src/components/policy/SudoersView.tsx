import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  fetchSudoersHosts,
  fetchSudoersConfig,
  saveSudoersConfig,
  deleteSudoersOverride,
  fetchSudoersSnapshots,
} from '@/api/sudoers'
import { parseSudoers, serializeSudoers, type SudoersRule } from '@/lib/sudoers'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'
import { Shield, Clock, AlertTriangle, CheckCircle2, Save, Trash2, RotateCcw, Plus, X, BookOpen } from 'lucide-react'
import { fmtDate } from '@/lib/date'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'

type Mode = 'visual' | 'raw'

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
                        <div className="flex items-center gap-1">
                          {h?.inSync ? (
                            <>
                              <CheckCircle2 size={13} className="text-green" />
                              <span className="text-[10px] text-green font-medium uppercase tracking-tight">In sync</span>
                            </>
                          ) : (
                            <>
                              <Clock size={13} className="text-amber" />
                              <span className="text-[10px] text-amber font-medium uppercase tracking-tight">Pending</span>
                            </>
                          )}
                        </div>
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
  const { data: snaps, isPending: p2 } = useQuery({
    queryKey: ['sudoers-snapshots', host],
    queryFn: () => fetchSudoersSnapshots(host),
    enabled: host !== '_default'
  })

  const [mode, setMode] = useState<Mode>('visual')
  const [rawContent, setRawContent] = useState<string | null>(null)
  const [rules, setRules] = useState<SudoersRule[] | null>(null)
  const [selectedRuleIdx, setSelectedRuleIdx] = useState<number>(-1)
  const [ruleFilter, setRuleFilter] = useState('')
  const [cmdInput, setCmdInput] = useState('')
  const cmdInputRef = useRef<HTMLInputElement>(null)
  const [revertConfirm, setRevertConfirm] = useState(false)

  const save = useMutation({
    mutationFn: (c: string) => saveSudoersConfig(host, c),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sudoers-config', host] })
      qc.invalidateQueries({ queryKey: ['sudoers-hosts'] })
      setRawContent(null)
      setRules(null)
    }
  })

  const remove = useMutation({
    mutationFn: () => deleteSudoersOverride(host),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sudoers-config', host] })
      qc.invalidateQueries({ queryKey: ['sudoers-hosts'] })
      setRawContent(null)
      setRules(null)
    }
  })

  if (p1 || (host !== '_default' && p2)) {
    return <div className="p-8 text-text-dim font-mono text-[13px]">Loading configuration…</div>
  }

  const serverContent = config?.content ?? ''
  const isGlobal = host === '_default'

  // Derive current working content
  const currentRaw = rawContent ?? serverContent
  const parsed = (() => {
    try { return parseSudoers(currentRaw) } catch { return { rules: [], aliases: [], advanced: '' } }
  })()
  const currentRules = rules ?? parsed.rules

  const getCurrentContent = (): string => {
    if (mode === 'raw') return currentRaw
    return serializeSudoers(currentRules, parsed.aliases, parsed.advanced)
  }

  const isDirty = (() => {
    const current = getCurrentContent()
    return current !== serverContent
  })()

  const switchMode = (newMode: Mode) => {
    if (newMode === mode) return
    if (newMode === 'raw') {
      setRawContent(serializeSudoers(currentRules, parsed.aliases, parsed.advanced))
      setRules(null)
    } else {
      const p = parseSudoers(currentRaw)
      setRules(p.rules)
      setRawContent(null)
    }
    setMode(newMode)
    setSelectedRuleIdx(-1)
  }

  const restoreSnapshot = (content: string) => {
    setRawContent(content)
    const p = parseSudoers(content)
    setRules(p.rules)
  }

  const addRule = () => {
    const newRule: SudoersRule = {
      principalType: 'user',
      principalName: '',
      hosts: 'ALL',
      runasUser: 'ALL',
      runasGroup: '',
      nopasswd: false,
      noexec: false,
      setenv: false,
      cmds: ['ALL']
    }
    const next = [newRule, ...currentRules]
    setRules(next)
    setSelectedRuleIdx(0)
  }

  const deleteRule = (idx: number) => {
    const next = currentRules.filter((_, i) => i !== idx)
    setRules(next)
    setSelectedRuleIdx(next.length ? 0 : -1)
  }

  const updateRule = (idx: number, patch: Partial<SudoersRule>) => {
    const next = currentRules.map((r, i) => i === idx ? { ...r, ...patch } : r)
    setRules(next)
  }

  const handleSave = () => save.mutate(getCurrentContent())

  const filteredRules = currentRules
    .map((r, i) => ({ r, i }))
    .filter(({ r }) => !ruleFilter || r.principalName.toLowerCase().includes(ruleFilter.toLowerCase()))

  const selectedRule = selectedRuleIdx >= 0 && selectedRuleIdx < currentRules.length
    ? currentRules[selectedRuleIdx]
    : null

  const canEdit = isGlobal || (config?.is_override ?? false) || isDirty

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Title row */}
      <div className="h-[44px] border-b border-border bg-surface px-4 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2">
          <Shield size={16} className={isGlobal ? "text-blue" : "text-green"} />
          <span className="text-[14px] font-bold text-text">
            {isGlobal ? 'Global sudoers Template' : `Override: ${host}`}
          </span>
          <span className="text-[11px] text-text-dim ml-1">
            {isGlobal ? '— base policy inherited by all hosts' : config?.is_override ? '— custom policy active' : '— inheriting global default'}
          </span>
        </div>
        <div className="flex items-center gap-2">
          {isDirty && (
            <Button variant="ghost" size="sm" onClick={() => { setRawContent(null); setRules(null) }} className="h-7 text-text-dim hover:text-text text-[12px]">
              <RotateCcw size={13} className="mr-1" /> Discard
            </Button>
          )}
          {!isGlobal && config?.is_override && (
            <Button variant="ghost" size="sm"
              onClick={() => setRevertConfirm(true)}
              className="h-7 text-text-dim hover:text-red text-[12px]"
            >
              <Trash2 size={13} className="mr-1" /> Revert
            </Button>
          )}
          <Button size="sm" disabled={!isDirty || save.isPending} onClick={handleSave}
            className="h-7 bg-green hover:bg-green/90 text-black font-bold px-4 rounded-[4px] text-[12px]"
          >
            <Save size={13} className="mr-1" /> {save.isPending ? 'Saving…' : 'Save Changes'}
          </Button>
        </div>
      </div>

      {/* Requirement Info Box */}
      <div className="bg-blue/5 border-b border-border/40 p-4 flex gap-4 items-start shrink-0">
        <BookOpen className="text-blue shrink-0 mt-0.5" size={18} />
        <div className="space-y-1.5 text-[12px] leading-relaxed">
          <p className="text-text font-bold">How sudoers management works</p>
          <p className="text-text-sub">
            Changes are written to <code className="bg-card px-1 py-0.5 rounded border border-border">/etc/sudoers.d/sudo-logger-managed</code>.
            The main <code className="bg-card px-1 py-0.5 rounded border border-border">/etc/sudoers</code> is <span className="text-blue font-bold">never</span> modified.
          </p>
          <p className="text-amber font-medium">
            ⚠️ Requirement: Your main <code className="bg-card px-1 py-0.5 rounded border border-border">/etc/sudoers</code> must contain <code className="bg-card px-1 py-0.5 rounded border border-border">#includedir /etc/sudoers.d</code> to enable these rules.
          </p>
        </div>
      </div>

      {/* Mode toggle toolbar */}
      <div className="h-[36px] border-b border-border bg-surface/60 px-4 flex items-center gap-3 shrink-0">
        <div className="flex rounded-[4px] border border-border overflow-hidden text-[12px]">
          <button
            onClick={() => switchMode('visual')}
            className={cn("px-4 py-1 font-semibold transition-colors", mode === 'visual' ? "bg-green text-black" : "text-text-dim hover:text-text hover:bg-card-hover")}
          >
            Visual Editor
          </button>
          <button
            onClick={() => switchMode('raw')}
            className={cn("px-4 py-1 font-semibold border-l border-border transition-colors", mode === 'raw' ? "bg-green text-black" : "text-text-dim hover:text-text hover:bg-card-hover")}
          >
            Raw
          </button>
        </div>
        {mode === 'visual' && (
          <span className="text-[11px] text-text-dim">Click a rule to edit · <strong className="text-text-sub">+&nbsp;New</strong> to add</span>
        )}
      </div>

      {/* Banner for non-override hosts */}
      {!isGlobal && !config?.is_override && !isDirty && (
        <div className="px-4 py-2.5 bg-blue/5 border-b border-blue/20 text-[12px] text-blue flex items-center gap-3">
          <span>🔗 <strong>Inheriting global default.</strong></span>
          <button
            onClick={() => { setRawContent(serverContent || ''); setRules(parseSudoers(serverContent || '').rules) }}
            className="text-[11px] border border-blue/30 text-blue px-2 py-0.5 rounded hover:bg-blue/10 transition-colors"
          >
            Create custom rules for {host}
          </button>
        </div>
      )}

      {/* Main content area */}
      <div className="flex-1 flex overflow-hidden" style={{ opacity: canEdit || isDirty ? 1 : 0.65, pointerEvents: canEdit || isDirty ? 'auto' : 'none' }}>
        {mode === 'raw' ? (
          <textarea
            value={currentRaw}
            onChange={e => setRawContent(e.target.value)}
            spellCheck={false}
            className="flex-1 bg-bg text-text font-mono text-[13px] p-6 outline-none resize-none leading-relaxed"
            placeholder="# Sudoers policy goes here..."
          />
        ) : (
          <>
            {/* Rules list column */}
            <div className="w-[300px] border-r border-border flex flex-col bg-surface shrink-0">
              <div className="p-2 border-b border-border flex gap-2">
                <input
                  value={ruleFilter}
                  onChange={e => setRuleFilter(e.target.value)}
                  placeholder="Search rules…"
                  className="flex-1 h-8 bg-bg border border-border rounded-[4px] px-2.5 text-[12px] text-text outline-none focus:border-green"
                />
                <button
                  onClick={addRule}
                  className="h-8 px-2.5 bg-green text-black text-[12px] font-bold rounded-[4px] flex items-center gap-1 hover:bg-green/90"
                >
                  <Plus size={13} /> New
                </button>
              </div>
              <div className="flex-1 overflow-y-auto">
                {filteredRules.length === 0 ? (
                  <p className="p-4 text-center text-[12px] text-text-dim italic">No rules defined.</p>
                ) : filteredRules.map(({ r, i }) => {
                  const icon = r.principalType === 'ad-group' ? '🌐' : r.principalType === 'group' ? '👥' : '👤'
                  return (
                    <button
                      key={i}
                      onClick={() => setSelectedRuleIdx(i)}
                      className={cn(
                        "w-full text-left px-3 py-2.5 border-b border-border transition-colors flex items-start justify-between gap-2",
                        selectedRuleIdx === i
                          ? "bg-card-active border-l-4 border-l-blue"
                          : "hover:bg-card-hover"
                      )}
                    >
                      <div className="overflow-hidden">
                        <div className={cn("text-[13px] font-semibold flex items-center gap-1.5", selectedRuleIdx === i ? "text-blue" : "text-text")}>
                          <span>{icon}</span>
                          <span className="truncate">{r.principalName || <span className="text-text-dim italic">unnamed</span>}</span>
                        </div>
                        <div className="text-[11px] text-text-dim font-mono truncate mt-0.5">
                          {r.cmds.join(', ') || 'ALL'}
                        </div>
                      </div>
                      <div className="flex flex-col gap-1 items-end shrink-0">
                        {r.nopasswd && <span className="text-[9px] text-green bg-green/10 px-1 rounded font-bold">NOPASSWD</span>}
                        {r.cwd && <span className="text-[9px] text-amber bg-amber/10 px-1 rounded font-bold">CWD</span>}
                      </div>
                    </button>
                  )
                })}
              </div>
            </div>

            {/* Inspector column */}
            <div className="flex-1 flex flex-col overflow-hidden bg-bg">
              {selectedRule ? (
                <RuleInspector
                  rule={selectedRule}
                  idx={selectedRuleIdx}
                  cmdInput={cmdInput}
                  cmdInputRef={cmdInputRef}
                  onUpdate={(patch) => updateRule(selectedRuleIdx, patch)}
                  onDelete={() => deleteRule(selectedRuleIdx)}
                  onCmdInput={setCmdInput}
                />
              ) : (
                <div className="flex-1 flex items-center justify-center text-text-dim text-[13px]">
                  Select a rule from the list to edit, or click <strong className="mx-1 text-green">+ New</strong> to add one.
                </div>
              )}
            </div>
          </>
        )}

        {/* Snapshots sidebar — raw mode only */}
        {mode === 'raw' && !isGlobal && (
          <div className="w-[280px] flex flex-col bg-surface overflow-hidden shrink-0 border-l border-border">
            <div className="p-3 border-b border-border">
              <h3 className="text-[11px] font-bold text-text-dim uppercase tracking-wider flex items-center gap-2">
                <Clock size={12} /> Snapshots
              </h3>
            </div>
            <div className="flex-1 overflow-y-auto p-2 space-y-2">
              {(snaps?.snapshots ?? []).map(s => (
                <button
                  key={s.sha256}
                  onClick={() => restoreSnapshot(s.content)}
                  title="Click to restore this snapshot"
                  className="w-full text-left p-2.5 rounded-[4px] border border-border bg-card hover:border-green hover:bg-green/5 transition-colors group"
                >
                  <div className="flex items-center justify-between mb-4">
                    <span className="text-[12px] font-bold text-text-sub group-hover:text-green">{fmtDate(s.uploaded_at)}</span>
                    <span className="text-[9px] font-mono text-text-dim">{s.sha256.substring(0, 8)}</span>
                  </div>
                  <div className="text-[11px] text-text-dim truncate font-mono bg-bg/50 p-1 rounded">
                    {s.content.split('\n').filter(l => l && !l.startsWith('#')).slice(0, 3).join(', ')}…
                  </div>
                  <div className="text-[10px] text-text-dim mt-1 opacity-0 group-hover:opacity-100 transition-opacity">↩ Click to restore</div>
                </button>
              ))}
              {(snaps?.snapshots ?? []).length === 0 && (
                <p className="p-4 text-center text-[12px] text-text-dim italic">No snapshots yet.</p>
              )}
            </div>
          </div>
        )}
      </div>
      <ConfirmDialog
        open={revertConfirm}
        title="Revert Override"
        message={`Revert "${host}" to global default? This will delete the host-specific override.`}
        confirmLabel="Revert"
        danger
        onConfirm={() => { remove.mutate(); setRevertConfirm(false) }}
        onCancel={() => setRevertConfirm(false)}
      />
    </div>
  )
}

interface RuleInspectorProps {
  rule: SudoersRule
  idx: number
  cmdInput: string
  cmdInputRef: React.RefObject<HTMLInputElement | null>
  onUpdate: (patch: Partial<SudoersRule>) => void
  onDelete: () => void
  onCmdInput: (v: string) => void
}

function RuleInspector({ rule, cmdInput, cmdInputRef, onUpdate, onDelete, onCmdInput }: RuleInspectorProps) {
  const [delConfirm, setDelConfirm] = useState(false)
  const addCmd = () => {
    const val = cmdInput.trim()
    if (!val) return
    onUpdate({ cmds: [...rule.cmds, val] })
    onCmdInput('')
    setTimeout(() => cmdInputRef.current?.focus(), 0)
  }

  const removeCmd = (ci: number) => {
    onUpdate({ cmds: rule.cmds.filter((_, i) => i !== ci) })
  }

  const isAdGroup = rule.principalType === 'ad-group'

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="px-5 py-3 border-b border-border bg-surface flex items-center justify-between shrink-0">
        <div>
          <span className="text-[14px] font-bold text-text">Access Rule Editor</span>
          {rule.principalName && (
            <span className="ml-2 text-[12px] font-mono text-text-dim">{rule.principalName}</span>
          )}
        </div>
        <button
          onClick={() => setDelConfirm(true)}
          className="text-[12px] border border-red/30 text-red/80 hover:border-red hover:text-red px-3 py-1 rounded-[4px] transition-colors"
        >
          Delete Rule
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* Principal */}
        <div className="flex gap-4">
          <div className="flex-1">
            <label className="block text-[10.5px] font-bold text-text-dim uppercase tracking-wider mb-2">Principal Type</label>
            <div className="flex rounded-[4px] border border-border overflow-hidden text-[12px]">
              {(['user', 'group', 'ad-group'] as const).map(t => (
                <button
                  key={t}
                  onClick={() => onUpdate({ principalType: t })}
                  className={cn(
                    "flex-1 py-1.5 font-semibold transition-colors border-r border-border last:border-r-0",
                    rule.principalType === t ? "bg-blue text-white" : "text-text-dim hover:text-text hover:bg-card-hover"
                  )}
                >
                  {t === 'user' ? '👤 User' : t === 'group' ? '👥 Local' : '🌐 AD Group'}
                </button>
              ))}
            </div>
          </div>
          <div className="flex-[1.5]">
            <label className="block text-[10.5px] font-bold text-text-dim uppercase tracking-wider mb-2">Name</label>
            <input
              type="text"
              value={rule.principalName}
              onChange={e => onUpdate({ principalName: e.target.value })}
              placeholder="username or %group"
              className="w-full h-9 bg-card border border-border-mid rounded-[4px] px-3 text-[13px] text-text outline-none focus:border-green"
            />
          </div>
        </div>

        {isAdGroup && (
          <div className="text-[11px] text-text-dim bg-blue/5 border border-blue/20 rounded-[4px] px-3 py-2">
            AD groups are written as <code className="text-blue">%{rule.principalName.replace(/ /g, '\\ ')}</code> — spaces are backslash-escaped for SSSD.
          </div>
        )}

        {/* Commands */}
        <div>
          <label className="block text-[10.5px] font-bold text-text-dim uppercase tracking-wider mb-2">Allowed Commands</label>
          <div className="border border-border-mid rounded-[4px] p-2 bg-card flex flex-wrap gap-1.5 min-h-[38px] items-center">
            {rule.cmds.map((c, ci) => (
              <span key={ci} className="flex items-center gap-1 bg-bg border border-border rounded-[3px] px-2 py-0.5 text-[12px] font-mono text-text-sub">
                {c}
                <button onClick={() => removeCmd(ci)} className="text-text-dim hover:text-red ml-0.5"><X size={11} /></button>
              </span>
            ))}
            <input
              ref={cmdInputRef}
              type="text"
              value={cmdInput}
              onChange={e => onCmdInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); addCmd() } }}
              placeholder="+ Type command…"
              className="border-none bg-transparent text-[12px] font-mono text-text outline-none flex-1 min-w-[140px]"
            />
          </div>
          <p className="text-[10.5px] text-text-dim mt-1">Press <kbd className="px-1 bg-card border border-border rounded text-[10px]">Enter</kbd> or <kbd className="px-1 bg-card border border-border rounded text-[10px]">,</kbd> to add a command.</p>
        </div>

        {/* Security Flags */}
        <div className="grid grid-cols-3 gap-3 bg-surface border border-border rounded-[4px] px-4 py-3">
          {([
            ['nopasswd', 'No password'],
            ['noexec',   'No shell escape'],
            ['setenv',   'Keep environment'],
          ] as const).map(([field, label]) => (
            <label key={field} className="flex items-center gap-2 cursor-pointer text-[12.5px]">
              <input
                type="checkbox"
                checked={rule[field]}
                onChange={e => onUpdate({ [field]: e.target.checked })}
                className="accent-green"
              />
              <span>{label}</span>
            </label>
          ))}
        </div>

        {/* Advanced */}
        <div>
          <div className="text-[10.5px] font-bold text-text-dim uppercase tracking-wider border-b border-border pb-2 mb-3">Advanced Limits &amp; Sandboxing</div>
          <div className="grid grid-cols-3 gap-3 mb-3">
            {([
              ['runasUser', 'Run As User'],
              ['runasGroup', 'Run As Group'],
              ['hosts', 'Hosts'],
            ] as const).map(([field, label]) => (
              <div key={field}>
                <label className="block text-[11px] text-text-dim mb-1">{label}</label>
                <input
                  type="text"
                  value={(rule[field] as string) || ''}
                  onChange={e => onUpdate({ [field]: e.target.value })}
                  className="w-full h-8 bg-card border border-border-mid rounded-[4px] px-2.5 text-[12px] font-mono text-text outline-none focus:border-green"
                />
              </div>
            ))}
          </div>
          <div className="grid grid-cols-3 gap-3">
            {([
              ['cwd',    'Working Dir (CWD)'],
              ['chroot', 'Chroot Jail'],
            ] as const).map(([field, label]) => (
              <div key={field}>
                <label className="block text-[11px] text-text-dim mb-1">{label}</label>
                <input
                  type="text"
                  value={(rule[field] as string) || ''}
                  onChange={e => onUpdate({ [field]: e.target.value || undefined })}
                  className="w-full h-8 bg-card border border-border-mid rounded-[4px] px-2.5 text-[12px] font-mono text-text outline-none focus:border-green"
                />
              </div>
            ))}
            <div>
              <label className="block text-[11px] text-text-dim mb-1">Timeout (Seconds)</label>
              <input
                type="number"
                value={rule.timeout ?? ''}
                onChange={e => onUpdate({ timeout: e.target.value ? parseInt(e.target.value, 10) : undefined })}
                className="w-full h-8 bg-card border border-border-mid rounded-[4px] px-2.5 text-[12px] font-mono text-text outline-none focus:border-green"
              />
            </div>
          </div>
        </div>
      </div>
      <ConfirmDialog
        open={delConfirm}
        title="Delete Rule"
        message="Delete this sudoers rule?"
        confirmLabel="Delete"
        danger
        onConfirm={() => { onDelete(); setDelConfirm(false) }}
        onCancel={() => setDelConfirm(false)}
      />
    </div>
  )
}
