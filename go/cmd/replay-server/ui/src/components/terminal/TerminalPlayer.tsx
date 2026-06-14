import { useEffect, useRef } from 'react'
import * as AsciinemaPlayer from 'asciinema-player'
import 'asciinema-player/dist/bundle/asciinema-player.css'
import { RiskBadge } from '../sessions/RiskBadge'
import type { SessionInfo } from '@/types/session'

interface Props {
  session: SessionInfo
}

export function TerminalPlayer({ session }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const playerRef = useRef<any>(null)

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
      fit: 'both', // Scale to fill viewport; server patches cast header for correct dims
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

      {/* Terminal — no padding so asciinema-player fills the entire area */}
      <div className="flex-1 overflow-hidden bg-black" ref={containerRef} />
    </div>
  )
}
