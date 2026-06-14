import { useState, useEffect } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { fetchMe } from '@/api/config'
import { fetchApprovals } from '@/api/approvals'
import { cn } from '@/lib/utils'
import { useCan } from '@/lib/perms'
import { useSessionStats } from '@/lib/sessionStats'
import { User, LogOut, Sun, Moon, BookOpen } from 'lucide-react'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from '@/components/ui/dialog'

function useTheme() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    return (localStorage.getItem('sudo-replay-theme') as 'dark' | 'light') || 'dark'
  })
  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('sudo-replay-theme', theme)
  }, [theme])
  const toggle = () => setTheme(t => t === 'dark' ? 'light' : 'dark')
  return { theme, toggle }
}

const tabs = [
  { to: '/',          label: 'Sessions',  perm: null              },
  { to: '/reports',   label: 'Reports',   perm: 'audit_log:read'  },
  { to: '/policy',    label: 'Policy',    perm: 'policy:read'     },
  { to: '/config',    label: 'Config',    perm: 'config:read'     },
  { to: '/approvals', label: 'Approvals', perm: 'approvals:read'  },
]

export function AppShell({ children }: { children: React.ReactNode }) {
  const { data: me } = useQuery({ queryKey: ['me'], queryFn: fetchMe })
  const { data: apprs } = useQuery({
    queryKey: ['approvals'],
    queryFn: fetchApprovals,
    refetchInterval: 5_000,
  })
  const can = useCan()
  const location = useLocation()
  const { theme, toggle: toggleTheme } = useTheme()

  const pendingCount = (apprs || []).filter(r => !r.status || r.status === 'pending').length
  const { shown, total } = useSessionStats()
  const visibleTabs = tabs.filter(t => !t.perm || can(t.perm))
  const [showHelp, setShowHelp] = useState(false)

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return
      if (e.key === '?') setShowHelp(v => !v)
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [])

  return (
    <div className="flex flex-col h-screen bg-bg text-text font-sans overflow-hidden transition-colors duration-200">
      <header className="border-b border-border bg-surface flex items-center justify-between px-4 h-[48px] shrink-0 z-50 shadow-sm">
        <div className="flex items-center gap-8">
          <div className="flex items-center gap-2.5">
            <img
              src="/logo-icon-72.svg"
              alt="sudo-logger"
              className="h-6 w-6"
              style={{ filter: 'drop-shadow(0 0 6px #00e87a99)' }}
            />
            <span className="font-bold text-[16px] text-foreground tracking-tight uppercase">SUDO-REPLAY</span>
            {total > 0 && (
              <span className="ml-1 px-2 py-0.5 rounded text-[11px] font-mono text-text-dim bg-card border border-border">
                {shown} / {total} sessions
              </span>
            )}
          </div>
          <nav className="flex gap-2">
            {visibleTabs.map(t => {
              const isActive = t.to === '/' ? location.pathname === '/' : location.pathname.startsWith(t.to)
              return (
                <NavLink
                  key={t.to}
                  to={t.to}
                  className={cn(
                    'px-4 py-1.5 text-[13px] rounded-[4px] transition-all font-semibold border-b-2 border-transparent hover:text-foreground',
                    isActive
                      ? 'text-green border-green bg-green/5'
                      : 'text-text-dim hover:bg-card-hover',
                  )}
                >
                  {t.label}
                  {t.label === 'Approvals' && pendingCount > 0 && (
                    <span className="ml-2 bg-red text-white text-[10px] font-bold rounded-full px-1.5 py-0.5 animate-pulse min-w-[18px] text-center">
                       {pendingCount}
                    </span>
                  )}
                </NavLink>
              )
            })}
          </nav>
        </div>
        <div className="flex items-center gap-5 text-xs text-text-dim">
          <label className="flex items-center gap-2 cursor-pointer hover:text-green transition-colors font-medium">
            <div className="relative">
              <input
                type="checkbox"
                className="sr-only peer"
                defaultChecked={localStorage.getItem('sudo-replay-autoplay') !== 'false'}
                onChange={e => localStorage.setItem('sudo-replay-autoplay', String(e.target.checked))}
              />
              <div className="w-8 h-4 bg-card rounded-full border border-border peer-checked:bg-green peer-checked:border-green transition-colors"></div>
              <div className="absolute left-[2px] top-[2px] w-3 h-3 bg-white rounded-full transition-transform peer-checked:translate-x-4"></div>
            </div>
            <span className="peer-checked:text-green flex items-center gap-1">
               {localStorage.getItem('sudo-replay-autoplay') !== 'false' && <span className="w-1.5 h-1.5 bg-green rounded-full animate-pulse" />}
               autoplay
            </span>
          </label>

          <div className="h-5 w-px bg-border/50" />

          <button
            onClick={toggleTheme}
            title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
            className="flex items-center justify-center w-7 h-7 border border-border rounded hover:border-border-mid hover:text-text-sub transition-colors"
          >
            {theme === 'dark' ? <Sun size={13} /> : <Moon size={13} />}
          </button>

          <div className="h-4 w-px bg-border-mid" />

          <a
            href="/docs/portal.html"
            target="_blank"
            rel="noopener noreferrer"
            title="Documentation"
            className="flex items-center justify-center w-7 h-7 border border-border rounded hover:border-border-mid hover:text-text-sub transition-colors"
          >
            <BookOpen size={13} />
          </a>

          <button
            onClick={() => setShowHelp(true)}
            title="Keyboard shortcuts"
            className="flex items-center justify-center w-7 h-7 border border-border rounded hover:border-border-mid hover:text-text-sub transition-colors font-bold text-[13px]"
          >?</button>

          <div className="h-4 w-px bg-border-mid" />

          {me && (
            <div className="flex items-center gap-2 text-text-sub font-mono">
              <User size={14} className="text-text-dim" />
              <span>{me.username}</span>
              <span className="text-[10px] bg-card border border-border px-1 rounded text-text-dim uppercase">{me.role}</span>
            </div>
          )}

          <a href="/oauth2/sign_out" className="flex items-center gap-1.5 hover:text-red transition-colors group">
            <LogOut size={14} className="text-text-dim group-hover:text-red" />
            Sign out
          </a>
        </div>
      </header>
      <main className="flex-1 overflow-hidden bg-bg">{children}</main>

      <Dialog open={showHelp} onOpenChange={setShowHelp}>
        <DialogContent className="max-w-[900px] w-[95vw] max-h-[85vh] overflow-y-auto bg-surface border-border text-text">
          <DialogHeader>
            <DialogTitle className="text-[16px] font-bold">Help &amp; Reference</DialogTitle>
          </DialogHeader>
          <div className="space-y-8 pt-2 text-[13px]">

            {/* Keyboard shortcuts */}
            <HelpSection title="Keyboard Shortcuts">
              <div className="grid grid-cols-2 gap-6">
                <div className="space-y-2">
                  <div className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-2">Player</div>
                  <KbdRow keys={['Space']} desc="Play / pause" />
                  <KbdRow keys={['←']}    desc="Seek back 5 seconds" />
                  <KbdRow keys={['→']}    desc="Seek forward 5 seconds" />
                </div>
                <div className="space-y-2">
                  <div className="text-[10px] font-bold text-text-dim uppercase tracking-wider mb-2">Navigation</div>
                  <KbdRow keys={['↑', '↓']} desc="Navigate session list" />
                  <KbdRow keys={['?']}       desc="Show this help" />
                </div>
              </div>
            </HelpSection>

            {/* Session indicators */}
            <HelpSection title="Session Indicators">
              <p className="text-text-dim mb-3">Badges shown on session cards.</p>
              <HelpTable cols={['Badge', 'Meaning']}>
                <HelpRow label={<Badge cls="bg-purple-900/40 text-purple-300 border-purple-500/40">ebpf</Badge>} desc="Session captured by the eBPF TTY recorder instead of the sudo plugin — e.g. su, screen, tmux. Fully recorded." />
                <HelpRow label={<Badge cls="bg-blue-900/40 text-blue-300 border-blue-500/40">pkexec</Badge>} desc="Privilege escalation via pkexec, captured by the eBPF execve tracepoint. No sudo plugin involved." />
                <HelpRow label={<Badge cls="bg-green/10 text-green border-green/40">live</Badge>} desc="Session is currently running. Replay shows whatever has been captured so far." />
                <HelpRow label={<Badge cls="bg-card text-text-sub border-border">⚠ incomplete</Badge>} desc="Session ended without a clean SESSION_END — agent was killed or crashed. Recording may be truncated." />
                <HelpRow label={<Badge cls="bg-card text-amber border-amber/40">⏱ network outage</Badge>} desc="Agent lost contact with log server. Processes were frozen until connectivity restored — recording is complete but delayed." />
                <HelpRow label={<Badge cls="bg-red/10 text-red border-red/40">⚠ no plugin</Badge>} desc="eBPF detected sudo but the audit plugin never logged a session. Plugin may not be installed or was bypassed. No full audit trail — investigate." />
              </HelpTable>
            </HelpSection>

            {/* Risk scoring */}
            <HelpSection title="Risk Scoring">
              <p className="text-text-dim mb-4">Every session is evaluated against all rules in <code className="bg-card border border-border px-1 rounded text-[12px]">/etc/sudo-logger/risk-rules.yaml</code>. Each matching rule adds its score (capped at 100). Scores are cached and recalculated when rules change.</p>
              <div className="flex gap-3 flex-wrap mb-4">
                {[
                  { label: 'Low',      range: '0 – 24',   cls: 'border-border-mid text-text-sub' },
                  { label: 'Medium',   range: '25 – 49',  cls: 'border-yellow-500/60 text-yellow-400' },
                  { label: 'High',     range: '50 – 74',  cls: 'border-orange-500/60 text-orange-400' },
                  { label: 'Critical', range: '75 – 100', cls: 'border-red/60 text-red' },
                ].map(l => (
                  <div key={l.label} className={`px-4 py-2 rounded-[6px] border ${l.cls} bg-card/30`}>
                    <div className="font-bold text-[13px]">{l.label}</div>
                    <div className="text-[12px] opacity-80">{l.range}</div>
                  </div>
                ))}
              </div>
            </HelpSection>

            {/* Data Redaction */}
            <HelpSection title="Data Redaction">
              <p className="text-text-dim mb-3">Secrets are masked by the local agent before being sent to the server. This protects sensitive credentials from appearing in recordings.</p>
              <HelpTable cols={['Protection', 'Description']}>
                <HelpRow label="Variable Masking"  desc="Automatically masks VAR=secret for common names like KEY, TOKEN, SECRET, PASSWORD." />
                <HelpRow label="Entropy Detection" desc="Catches assignments with long random values (24+ chars) even if the variable name is unknown (e.g. KALLE=...)." />
                <HelpRow label="SSH & Certificates" desc="Identifies and masks PEM-encoded private keys (SSH, SSL/TLS) and AWS/GitHub/Stripe tokens." />
                <HelpRow label="Custom Rules"     desc="Global regex patterns can be added via Config → Redaction to protect organization-specific data." />
              </HelpTable>
            </HelpSection>

            {/* Rule fields */}
            <HelpSection title="Rule Fields">
              <HelpTable cols={['Field', 'Description']}>
                <HelpRow label="Score"  desc="Points added to the session when this rule matches (1–100). Multiple matching rules accumulate." />
                <HelpRow label="ID"     desc="Unique identifier used internally. Use snake_case — e.g. stop_auditd." />
                <HelpRow label="Reason" desc="Short label shown in the session info bar, risk badge tooltip, and Anomalies tab." />
              </HelpTable>
            </HelpSection>

            {/* Command matching */}
            <HelpSection title="Command Matching">
              <p className="text-text-dim mb-3">Matched against the full sudo command line — everything after <code className="bg-card border border-border px-1 rounded text-[12px]">sudo</code>.</p>
              <HelpTable cols={['Field', 'Description']}>
                <HelpRow label="Must contain one of"    desc="The command line must include at least one of the listed substrings. Example: auditd, audit — matches 'systemctl stop auditd'." />
                <HelpRow label="AND one of"             desc="The command must also contain at least one of these. Use to require two independent keywords — e.g. stop and disable." />
                <HelpRow label="Command name is one of" desc="Matches just the program name (basename of argv[0]). More reliable for shell interpreters — e.g. bash, sh, zsh, python3." />
              </HelpTable>
            </HelpSection>

            {/* Shell content matching */}
            <HelpSection title="Shell Content Matching">
              <p className="text-text-dim mb-3">Scans terminal output (ttyout) for interactive sessions such as <code className="bg-card border border-border px-1 rounded text-[12px]">sudo bash</code>. Useful for detecting commands typed inside a shell — invisible to command-line matching.</p>
              <HelpTable cols={['Field', 'Description']}>
                <HelpRow label="Must contain one of" desc="At least one of the listed substrings must appear in the terminal output. Case-insensitive; ANSI escape codes are stripped first." />
                <HelpRow label="AND one of"          desc="The terminal output must also contain at least one of these — use to require two separate indicators." />
              </HelpTable>
            </HelpSection>

            {/* Session metadata */}
            <HelpSection title="Session Metadata Conditions">
              <HelpTable cols={['Field', 'Description']}>
                <HelpRow label="Runas user"          desc="Only match sessions where sudo ran as this user. Leave blank to match any. Default is root." />
                <HelpRow label="Min duration"        desc="Only match sessions that lasted at least this many seconds. Useful for flagging unusually long interactive shells." />
                <HelpRow label="Incomplete session"  desc="Only match sessions that ended without a clean SESSION_END — e.g. the agent was killed." />
                <HelpRow label="After business hours" desc="Only match sessions started between 23:00 and 05:59." />
              </HelpTable>
            </HelpSection>

            {/* Logic */}
            <HelpSection title="How Conditions Combine">
              <div className="space-y-3">
                {[
                  { badge: 'AND', color: 'bg-blue/20 text-blue border-blue/40', text: 'All conditions in a single rule must be satisfied. A rule with both a command pattern and Runas = root only fires when both are true.' },
                  { badge: 'OR',  color: 'bg-green/20 text-green border-green/40', text: 'Items within a tag list are alternatives — any one of them is enough. Listing auditd and rsyslog in "Must contain one of" matches either word.' },
                  { badge: 'OR',  color: 'bg-green/20 text-green border-green/40', text: 'Command matching and shell content matching are alternatives — a rule fires if either the command or the content pattern matches (while all other conditions still hold).' },
                ].map((r, i) => (
                  <div key={i} className="flex items-start gap-3">
                    <span className={`shrink-0 text-[10px] font-black px-2 py-0.5 rounded border ${r.color}`}>{r.badge}</span>
                    <span className="text-text-sub">{r.text}</span>
                  </div>
                ))}
              </div>
            </HelpSection>

            {/* Examples */}
            <HelpSection title="Examples">
              <div className="space-y-4">
                {[
                  { title: 'Detect stopping the audit daemon', desc: 'Matches any sudo command containing both "auditd" and one of "stop" / "disable" / "mask".', yaml: `score: 80\nid:    stop_auditd\nreason: Audit daemon stopped or disabled\ncommand:\n  contains_any: [auditd]\n  also_any:     [stop, disable, mask]` },
                  { title: 'Detect interactive root shell',    desc: 'Fires when the command basename is a shell interpreter — regardless of arguments.', yaml: `score: 50\nid:    root_shell\nreason: Direct root shell\ncommand_base_any: [bash, sh, zsh, fish, ksh]` },
                  { title: 'Detect passwd manipulation inside a shell', desc: 'Scans terminal output for commands that modify /etc/passwd or /etc/shadow.', yaml: `score: 70\nid:    passwd_tamper\nreason: Auth file manipulation\ncontent:\n  contains_any: [/etc/passwd, /etc/shadow, /etc/sudoers]` },
                ].map(ex => (
                  <div key={ex.title} className="bg-card border border-border rounded-[6px] p-4 space-y-2">
                    <div className="font-bold text-text">{ex.title}</div>
                    <div className="text-text-dim text-[12px]">{ex.desc}</div>
                    <pre className="bg-bg border border-border/50 rounded-[4px] px-3 py-2 text-[11px] font-mono text-blue/90 whitespace-pre">{ex.yaml}</pre>
                  </div>
                ))}
              </div>
            </HelpSection>

            {/* Tips */}
            <HelpSection title="Tips">
              <ul className="space-y-2 text-text-sub list-disc list-inside">
                <li>Use <strong>Command name is one of</strong> for shell interpreters — more precise than substring matching since it only checks the program name.</li>
                <li>Shell content matching reads up to 512 KB of terminal output. Only useful for sessions where a shell was invoked interactively.</li>
                <li>Scores accumulate across rules. A session matching three rules with scores 30, 40, and 20 gets a total of 90 (Critical).</li>
                <li>Leave unused fields empty — only filled fields are evaluated. An empty rule matches every session.</li>
                <li>Changes to risk rules take effect immediately. Cached scores are invalidated automatically on next load.</li>
              </ul>
            </HelpSection>

          </div>
          <div className="border-t border-border pt-4 flex justify-end">
            <a
              href="/docs/portal.html"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 text-[12px] text-text-dim hover:text-green transition-colors"
            >
              <BookOpen size={13} />
              Full documentation →
            </a>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  )
}

function KbdRow({ keys, desc }: { keys: string[]; desc: string }) {
  return (
    <div className="flex items-center gap-3">
      <div className="flex gap-1 shrink-0">
        {keys.map(k => (
          <kbd key={k} className="px-1.5 py-0.5 rounded-[3px] bg-card border border-border font-mono text-[11px] text-text-sub">{k}</kbd>
        ))}
      </div>
      <span className="text-text-sub">{desc}</span>
    </div>
  )
}

function HelpSection({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h3 className="text-[11px] font-bold text-text-dim uppercase tracking-[0.12em] mb-3 pb-1.5 border-b border-border">{title}</h3>
      {children}
    </div>
  )
}

function HelpTable({ cols, children }: { cols: string[]; children: React.ReactNode }) {
  return (
    <table className="w-full text-[13px] border-collapse">
      <thead>
        <tr>
          {cols.map(c => (
            <th key={c} className="text-left text-[11px] font-bold text-text-dim uppercase tracking-wider pb-2 pr-4">{c}</th>
          ))}
        </tr>
      </thead>
      <tbody>{children}</tbody>
    </table>
  )
}

function HelpRow({ label, desc }: { label: React.ReactNode; desc: string }) {
  return (
    <tr className="border-t border-border/40">
      <td className="py-2 pr-6 align-top font-mono text-[12px] text-text whitespace-nowrap">{label}</td>
      <td className="py-2 text-text-sub">{desc}</td>
    </tr>
  )
}

function Badge({ children, cls }: { children: React.ReactNode; cls: string }) {
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded-[3px] border text-[11px] font-mono ${cls}`}>{children}</span>
  )
}
