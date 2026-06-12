import { useEffect, useRef, useState, useCallback } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { fetchSessionEvents } from '@/api/sessions'
import { fmtDuration } from '@/lib/date'
import type { SessionInfo, SessionEvent } from '@/types/session'
import '@xterm/xterm/css/xterm.css'

interface Props {
  session: SessionInfo
}

export function TerminalPlayer({ session }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const termRef      = useRef<Terminal | null>(null)
  const fitRef       = useRef<FitAddon | null>(null)
  const rafRef       = useRef<number>(0)

  const [events, setEvents]   = useState<SessionEvent[]>([])
  const [loading, setLoading] = useState(false)
  const [playing, setPlaying] = useState(false)
  const [elapsed, setElapsed] = useState(0)
  const [speed, setSpeed]     = useState(1)

  const playingRef  = useRef(false)
  const elapsedRef  = useRef(0)
  const speedRef    = useRef(1)
  const eventsRef   = useRef<SessionEvent[]>([])
  const eventIdxRef = useRef(0)
  const lastRafTs   = useRef(0)

  useEffect(() => {
    if (!containerRef.current) return
    const term = new Terminal({
      theme: { background: '#09090f', foreground: '#d4daf0', cursor: '#d4daf0' },
      fontSize: 13,
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
      cursorBlink: false,
      convertEol: true,
      lineHeight: 1.3,
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(containerRef.current)
    fit.fit()
    termRef.current = term
    fitRef.current  = fit

    const observer = new ResizeObserver(() => fit.fit())
    observer.observe(containerRef.current)

    return () => {
      observer.disconnect()
      term.dispose()
    }
  }, [])

  useEffect(() => {
    setLoading(true)
    setPlaying(false)
    playingRef.current  = false
    setElapsed(0)
    elapsedRef.current  = 0
    eventIdxRef.current = 0
    termRef.current?.clear()

    fetchSessionEvents(session.tsid)
      .then(evs => {
        setEvents(evs)
        eventsRef.current = evs
        const auto = localStorage.getItem('sudo-replay-autoplay') !== 'false'
        if (auto) setTimeout(() => play(), 100)
      })
      .finally(() => setLoading(false))
  }, [session.tsid])

  const tick = useCallback((ts: number) => {
    if (!playingRef.current) return
    const dt = lastRafTs.current ? (ts - lastRafTs.current) / 1000 * speedRef.current : 0
    lastRafTs.current = ts
    elapsedRef.current += dt
    setElapsed(elapsedRef.current)

    const evs = eventsRef.current
    while (
      eventIdxRef.current < evs.length &&
      evs[eventIdxRef.current].t <= elapsedRef.current
    ) {
      const ev = evs[eventIdxRef.current++]
      if (ev.type === 4 && ev.data) {
        termRef.current?.write(atob(ev.data))
      } else if (ev.type === 'resize' && ev.cols && ev.rows) {
        termRef.current?.resize(ev.cols, ev.rows)
      }
    }

    if (eventIdxRef.current >= evs.length && evs.length > 0) {
      setPlaying(false)
      playingRef.current = false
      return
    }

    rafRef.current = requestAnimationFrame(tick)
  }, [])

  const play = useCallback(() => {
    if (eventsRef.current.length === 0) return
    if (eventIdxRef.current >= eventsRef.current.length) {
      restart()
      return
    }
    playingRef.current = true
    lastRafTs.current  = 0
    setPlaying(true)
    rafRef.current = requestAnimationFrame(tick)
  }, [tick])

  const pause = useCallback(() => {
    playingRef.current = false
    cancelAnimationFrame(rafRef.current)
    setPlaying(false)
  }, [])

  const restart = useCallback(() => {
    pause()
    elapsedRef.current  = 0
    eventIdxRef.current = 0
    setElapsed(0)
    termRef.current?.clear()
    play()
  }, [pause, play])

  const seek = useCallback((targetSecs: number) => {
    pause()
    termRef.current?.clear()
    elapsedRef.current  = targetSecs
    eventIdxRef.current = 0
    setElapsed(targetSecs)

    const evs = eventsRef.current
    while (
      eventIdxRef.current < evs.length &&
      evs[eventIdxRef.current].t <= targetSecs
    ) {
      const ev = evs[eventIdxRef.current++]
      if (ev.type === 4 && ev.data) {
        termRef.current?.write(atob(ev.data))
      }
    }
  }, [pause])

  const totalDuration = events.length > 0 ? events[events.length - 1].t : session.duration

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement).tagName
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return

      if (e.code === 'Space') {
        e.preventDefault()
        playingRef.current ? pause() : play()
      } else if (e.code === 'ArrowLeft') {
        e.preventDefault()
        seek(Math.max(0, elapsedRef.current - 5))
      } else if (e.code === 'ArrowRight') {
        e.preventDefault()
        seek(Math.min(totalDuration, elapsedRef.current + 5))
      } else if (e.code === 'KeyR') {
        e.preventDefault()
        restart()
      }
    }

    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [pause, play, restart, seek, totalDuration])

  const fillPct = totalDuration > 0 ? Math.min(100, Math.max(0, (elapsed / totalDuration) * 100)) : 0

  return (
    <div className="flex flex-col h-full bg-[#09090f] overflow-hidden relative">
      {/* Detailed Session Header */}
      <div className="bg-[#0e0e15] border-b border-border p-4 space-y-4 shrink-0 z-30 shadow-md shadow-black/30">
        {/* Row 1: Primary Identity */}
        <div className="flex items-center justify-center gap-x-8 text-[11px] font-black uppercase tracking-[0.15em]">
           <div className="flex gap-2 items-baseline">
              <span className="text-green/60">user</span>
              <span className="text-white text-[13px] tracking-tight lowercase font-mono">{session.user}</span>
           </div>
           <div className="flex gap-2 items-baseline">
              <span className="text-green/60">host</span>
              <span className="text-white text-[13px] tracking-tight lowercase font-mono">{session.host}</span>
           </div>
           <div className="flex gap-2 items-baseline">
              <span className="text-green/60">runas</span>
              <span className="text-white text-[13px] tracking-tight lowercase font-mono">{session.runas}</span>
           </div>
           <div className="flex gap-2 items-baseline">
              <span className="text-green/60">cmd</span>
              <span className="text-white text-[13px] tracking-tight lowercase font-mono">{session.command}</span>
           </div>
        </div>

        {/* Row 2: Incomplete Banner (Conditional) */}
        {session.incomplete && (
          <div className="max-w-4xl mx-auto py-1 px-4 bg-red-950/40 border border-red-500/30 rounded-[4px] flex items-center justify-center gap-3 text-[11px] text-red-400 font-bold uppercase tracking-widest animate-pulse">
             <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>
             Session incomplete — agent was killed or crashed before session_end. Recording may be truncated.
          </div>
        )}

        {/* Row 3: Risk & Reasons */}
        <div className="flex flex-col items-center gap-1">
           <div className="flex items-center gap-3">
              <RiskBadge level={session.risk_level} score={session.risk_score} className="scale-110" />
              <span className="text-text-dim text-[12px] font-medium tracking-tight">
                 {session.risk_reasons?.join(' — ') || 'No significant risk anomalies detected'}
              </span>
           </div>
           <div className="flex items-center gap-6 text-[10px] text-text-dim/60 font-mono mt-1 uppercase tracking-widest">
              <div className="flex gap-2"><span>bin</span> <span className="text-text-sub lowercase">{session.bin || 'unknown'}</span></div>
              <div className="flex gap-2"><span>cwd</span> <span className="text-text-sub lowercase">{session.cwd || '/'}</span></div>
              {session.flags && <div className="flex gap-2"><span>flags</span> <span className="text-text-sub lowercase">{session.flags}</span></div>}
           </div>
        </div>
      </div>

      {/* Terminal Viewport */}
      <div className="flex-1 overflow-hidden relative flex flex-col items-center justify-center p-6 pb-24">
         <div className="w-full max-w-[1200px] h-full shadow-2xl shadow-black/80 border border-border/20 rounded-lg overflow-hidden bg-black">
            <div ref={containerRef} className="w-full h-full p-2" />
         </div>
      </div>

      {/* Controls Bar - Fixed at bottom */}
      <div className="absolute bottom-0 left-0 right-0 z-40 bg-surface/95 backdrop-blur-md border-t border-border px-6 py-3 flex items-center gap-4 shadow-[0_-10px_30px_rgba(0,0,0,0.5)]">
        <button
          onClick={restart}
          disabled={loading || events.length === 0}
          title="Restart (R)"
          className="w-9 h-9 flex items-center justify-center rounded-full bg-card border border-border text-text-dim hover:text-white hover:border-border-mid transition-all shrink-0"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
        </button>

        <button
          onClick={playing ? pause : play}
          disabled={loading || events.length === 0}
          title="Play/Pause (Space)"
          className="w-11 h-9 flex items-center justify-center rounded-md bg-green border border-green text-black hover:bg-green/90 transition-all shrink-0 shadow-[0_0_15px_rgba(0,232,122,0.3)]"
        >
          {playing ? (
             <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>
          ) : (
             <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          )}
        </button>

        <div className="text-[13px] text-green font-mono font-bold min-w-[50px] shrink-0">
          {fmtDuration(elapsed)}
        </div>

        <div className="flex-1 group">
          <input
            type="range"
            min={0}
            max={totalDuration}
            step={0.1}
            value={elapsed}
            onChange={e => seek(Number(e.target.value))}
            disabled={loading || events.length === 0}
            className="w-full h-1.5 rounded-full outline-none cursor-pointer appearance-none bg-border/30 overflow-hidden"
            style={{
              background: `linear-gradient(to right, var(--color-green) 0%, var(--color-green) ${fillPct}%, #1e1e2e ${fillPct}%, #1e1e2e 100%)`
            }}
          />
        </div>

        <div className="text-[13px] text-text-dim font-mono min-w-[50px] shrink-0">
          {fmtDuration(totalDuration)}
        </div>

        <div className="flex items-center bg-card border border-border rounded-md px-2 h-9 shrink-0">
           <select
             value={speed}
             onChange={e => {
               speedRef.current = Number(e.target.value)
               setSpeed(Number(e.target.value))
             }}
             disabled={loading || events.length === 0}
             className="bg-transparent text-text-sub font-mono text-[12px] outline-none cursor-pointer border-none"
           >
             {[0.25, 0.5, 1, 1.5, 2, 4, 8, 16].map(s => (
               <option key={s} value={s} className="bg-[#12121a]">{s}x</option>
             ))}
           </select>
        </div>

        {loading && <div className="absolute top-[-30px] right-6 px-3 py-1 bg-green/10 border border-green/20 rounded-full text-[10px] text-green font-bold uppercase tracking-widest animate-pulse">Streaming data...</div>}
      </div>
    </div>
  )
}
