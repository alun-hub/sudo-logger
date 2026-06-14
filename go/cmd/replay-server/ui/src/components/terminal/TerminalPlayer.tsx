import { useEffect, useRef, useState } from 'react'
import * as AsciinemaPlayer from 'asciinema-player'
import 'asciinema-player/dist/bundle/asciinema-player.css'
import { RiskBadge } from '../sessions/RiskBadge'
import { fmtDate, fmtDuration } from '@/lib/date'
import type { SessionInfo } from '@/types/session'

interface Props {
  session: SessionInfo
}

export function TerminalPlayer({ session }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const playerRef = useRef<any>(null)
  const [copied, setCopied] = useState(false)

  function copyTsid() {
    navigator.clipboard.writeText(session.tsid).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }

  useEffect(() => {
    if (!containerRef.current) return

    const castUrl = `/api/session/cast?tsid=${encodeURIComponent(session.tsid)}`

    // Clean up previous player instance
    if (playerRef.current) {
      playerRef.current.dispose()
    }

    playerRef.current = AsciinemaPlayer.create(castUrl, containerRef.current, {
      autoPlay: localStorage.getItem('sudo-replay-autoplay') !== 'false',
      speed: 1.0,
      idleTimeLimit: 2,
      theme: 'asciinema',
      terminalFontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
      terminalLineHeight: 1.1,
      fit: 'both', // Scale to fill entire container; player reserves space for controls
    })

    return () => {
      if (playerRef.current) {
        playerRef.current.dispose()
        playerRef.current = null
      }
    }
  }, [session.tsid])

  return (
    <div className="flex flex-col h-full bg-bg overflow-hidden">
      {/* Compact single-row header */}
      <div className="bg-surface border-b border-border px-4 py-2 shrink-0 flex items-center gap-4 min-w-0">
        <div className="flex items-center gap-5 font-mono text-[12px] flex-1 min-w-0 overflow-hidden">
          <span className="flex gap-1.5 shrink-0">
            <span className="text-green/70 uppercase text-[10px] font-bold tracking-wider self-center">user</span>
            <span className="text-foreground">{session.user}</span>
          </span>
          <span className="flex gap-1.5 shrink-0">
            <span className="text-green/70 uppercase text-[10px] font-bold tracking-wider self-center">host</span>
            <span className="text-foreground">{session.host}</span>
          </span>
          <span className="flex gap-1.5 shrink-0">
            <span className="text-green/70 uppercase text-[10px] font-bold tracking-wider self-center">runas</span>
            <span className="text-foreground">{session.runas}</span>
          </span>
          <span className="flex gap-1.5 min-w-0">
            <span className="text-green/70 uppercase text-[10px] font-bold tracking-wider self-center shrink-0">cmd</span>
            <span className="text-foreground truncate">{session.command}</span>
          </span>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          {session.risk_reasons && session.risk_reasons.length > 0 && (
            <span className="text-[11px] text-text-dim hidden lg:block truncate max-w-[240px]">
              {session.risk_reasons[0]}
            </span>
          )}
          <RiskBadge level={session.risk_level} score={session.risk_score} />
          {session.incomplete && (
            <span className="text-[10px] text-red-400 font-bold uppercase tracking-widest animate-pulse">
              INCOMPLETE
            </span>
          )}
        </div>
      </div>

      {/* Terminal — fit:both scales to fill all available space */}
      <div className="flex-1 overflow-hidden bg-black" ref={containerRef} />

      {/* Bottom info bar */}
      <div className="bg-surface border-t border-border px-4 py-1.5 shrink-0 flex items-center gap-4 font-mono text-[11px] text-text-sub min-w-0">
        <span className="shrink-0">{fmtDate(session.start_time)}</span>
        <span className="text-border-mid">│</span>
        <span className="shrink-0">{fmtDuration(session.duration)}</span>
        {session.cwd && (
          <>
            <span className="text-border-mid">│</span>
            <span className="truncate text-text-dim min-w-0">{session.cwd}</span>
          </>
        )}
        <span className="flex-1" />
        <button
          onClick={copyTsid}
          title="Kopiera session-ID"
          className="shrink-0 text-text-dim hover:text-foreground transition-colors cursor-pointer"
        >
          {copied ? 'kopierat ✓' : `id: ${session.tsid.split('/').pop()}`}
        </button>
        <span className="text-border-mid">│</span>
        <a
          href={`/api/session/cast?tsid=${encodeURIComponent(session.tsid)}`}
          download
          title="Ladda ner .cast-fil"
          className="shrink-0 text-text-dim hover:text-foreground transition-colors"
        >
          ↓ .cast
        </a>
      </div>
    </div>
  )
}
