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
      terminalLineHeight: 1.3,
      fit: 'both', // Scale perfectly within both width and height constraints
    })

    return () => {
      if (playerRef.current) {
        playerRef.current.dispose()
        playerRef.current = null
      }
    }
  }, [session.tsid])

  return (
    <div className="flex flex-col h-full bg-bg overflow-hidden relative transition-colors duration-200">
      {/* Detailed Session Header */}
      <div className="bg-surface border-b border-border p-4 space-y-4 shrink-0 z-30 shadow-md shadow-black/5 transition-colors">
        <div className="flex items-center justify-center gap-x-8 text-[11px] font-black uppercase tracking-[0.15em]">
           <div className="flex gap-2 items-baseline">
              <span className="text-green/80">user</span>
              <span className="text-foreground text-[13px] tracking-tight lowercase font-mono">{session.user}</span>
           </div>
           <div className="flex gap-2 items-baseline">
              <span className="text-green/80">host</span>
              <span className="text-foreground text-[13px] tracking-tight lowercase font-mono">{session.host}</span>
           </div>
           <div className="flex gap-2 items-baseline">
              <span className="text-green/80">runas</span>
              <span className="text-foreground text-[13px] tracking-tight lowercase font-mono">{session.runas}</span>
           </div>
           <div className="flex gap-2 items-baseline">
              <span className="text-green/80">cmd</span>
              <span className="text-foreground text-[13px] tracking-tight lowercase font-mono">{session.command}</span>
           </div>
        </div>

        {session.incomplete && (
          <div className="max-w-4xl mx-auto py-1 px-4 bg-red-950/40 border border-red-500/30 rounded-[4px] flex items-center justify-center gap-3 text-[11px] text-red-400 font-bold uppercase tracking-widest animate-pulse">
             <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
             Session incomplete — agent was killed or crashed before session_end. Recording may be truncated.
          </div>
        )}

        <div className="flex flex-col items-center gap-1">
           <div className="flex items-center gap-3">
              <RiskBadge level={session.risk_level} score={session.risk_score} className="scale-110" />
              <span className="text-text-dim text-[12px] font-medium tracking-tight">
                 {session.risk_reasons?.join(' — ') || 'No significant risk anomalies detected'}
              </span>
           </div>
           <div className="flex items-center gap-6 text-[10px] text-text-dim/60 font-mono mt-1 uppercase tracking-widest">
              <div className="flex gap-2"><span>bin</span> <span className="text-text-sub lowercase">{session.resolved_command || 'unknown'}</span></div>
              <div className="flex gap-2"><span>cwd</span> <span className="text-text-sub lowercase">{session.cwd || '/'}</span></div>
              {session.flags && <div className="flex gap-2"><span>flags</span> <span className="text-text-sub lowercase">{session.flags}</span></div>}
           </div>
        </div>
      </div>

      {/* Terminal Viewport */}
      <div className="flex-1 overflow-hidden relative bg-black p-4">
         {/* Container strictly styled for asciinema fit="both" by expanding to full absolute dimensions */}
         <div ref={containerRef} className="absolute inset-4 flex items-center justify-center" />
      </div>
    </div>
  )
}
