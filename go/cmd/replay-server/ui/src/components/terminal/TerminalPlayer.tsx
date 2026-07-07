import { useEffect, useRef, useState } from 'react'
import * as AsciinemaPlayer from 'asciinema-player'
import 'asciinema-player/dist/bundle/asciinema-player.css'
import { VideoOff } from 'lucide-react'
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
  // 'loading' while we check the cast has playable content; asciinema-player
  // itself shows an unhelpful crash icon for a cast with a header but zero
  // events (e.g. a session that recorded no terminal I/O, or a stale
  // in-progress placeholder), or when the cast is missing entirely — both
  // real cases in this dataset, not just a hypothetical edge case.
  const [castState, setCastState] = useState<'loading' | 'empty' | 'ready'>('loading')

  function copyTsid() {
    navigator.clipboard.writeText(session.tsid).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }

  useEffect(() => {
    setCastState('loading')
    const controller = new AbortController()
    const castUrl = `/api/session/cast?tsid=${encodeURIComponent(session.tsid)}`

    if (playerRef.current) {
      playerRef.current.dispose()
      playerRef.current = null
    }

    fetch(castUrl, { signal: controller.signal })
      .then(res => (res.ok ? res.text() : Promise.reject(new Error(`HTTP ${res.status}`))))
      .then(text => {
        if (controller.signal.aborted) return
        // First line is the asciinema header; anything beyond that is an
        // actual playback event. No event lines means nothing to play.
        const hasEvents = text.split('\n').filter(l => l.trim() !== '').length > 1
        if (!hasEvents) {
          setCastState('empty')
          return
        }
        setCastState('ready')
        if (!containerRef.current) return
        playerRef.current = AsciinemaPlayer.create(castUrl, containerRef.current, {
          autoPlay: localStorage.getItem('sudo-replay-autoplay') !== 'false',
          speed: 1.0,
          idleTimeLimit: 2,
          theme: 'asciinema',
          terminalFontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
          terminalLineHeight: 1.1,
          fit: 'both', // Scale to fill entire container; player reserves space for controls
        })
      })
      .catch(err => {
        if (controller.signal.aborted) return
        console.error('failed to load session cast:', err)
        setCastState('empty')
      })

    return () => {
      controller.abort()
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
      <div className="flex-1 overflow-hidden bg-black relative">
        <div ref={containerRef} className="w-full h-full" style={{ display: castState === 'ready' ? undefined : 'none' }} />
        {castState === 'empty' && (
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="flex flex-col items-center gap-3 text-text-dim font-mono text-[13px] max-w-[420px] text-center px-6">
              <VideoOff size={28} className="opacity-50" />
              <span>No output was recorded for this session.</span>
              <span className="text-[11px] text-text-dim/70">
                This can happen for a non-interactive command, or a session that never received a clean end signal.
              </span>
            </div>
          </div>
        )}
      </div>

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
