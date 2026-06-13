import { useEffect, useRef, useState, useCallback } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { fetchSessionEvents } from '@/api/sessions'
import { fmtDuration } from '@/lib/date'
import { RiskBadge } from '../sessions/RiskBadge'
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

  // 1. Terminal Initialization & Parity
  useEffect(() => {
    if (!containerRef.current) return

    // HEURISTIC: Backend defaults to 220x50 if unknown.
    // This breaks vi if the real session was smaller.
    // If we see these suspicious defaults, we let FitAddon decide the grid.
    const hasRealDims = session.cols && session.rows && session.cols !== 220 && session.rows !== 50

    const term = new Terminal({
      theme: {
        background: '#09090f',
        foreground: '#d4daf0',
        cursor: '#00e87a',
        cursorAccent: '#09090f',
        selectionBackground: 'rgba(77,168,255,0.25)',
        black:'#1e2230',red:'#ff5f6d',green:'#00e87a',yellow:'#ffd666',
        blue:'#4da8ff',magenta:'#c984f8',cyan:'#4dd5f8',white:'#d4daf0',
        brightBlack:'#4a5068',brightRed:'#ff8089',brightGreen:'#33ffaa',
        brightYellow:'#ffe080',brightBlue:'#80c4ff',brightMagenta:'#d9aaff',
        brightCyan:'#80e8ff',brightWhite:'#eef0ff',
      },
      fontSize: 13,
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
      cursorBlink: true,
      convertEol: true,
      lineHeight: 1.3,
      cols: hasRealDims ? session.cols : undefined,
      rows: hasRealDims ? session.rows : undefined,
      scrollback: 5000,
    })

    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(containerRef.current)

    termRef.current = term
    fitRef.current  = fit

    // 2. Robust Sizing Logic
    const syncSize = () => {
      if (!containerRef.current || !termRef.current || !fitRef.current) return
      try {
        fitRef.current.fit()
        // If we have real dimensions, re-apply them AFTER fit has calculated the base size
        if (hasRealDims) {
          termRef.current.resize(session.cols!, session.rows!)
        }
      } catch (e) {}
    }

    // Multiple attempts to handle React view transition timing
    const timers = [
      setTimeout(syncSize, 50),
      setTimeout(syncSize, 250),
      setTimeout(syncSize, 1000)
    ]

    const observer = new ResizeObserver(syncSize)
    observer.observe(containerRef.current)

    return () => {
      observer.disconnect()
      timers.forEach(clearTimeout)
      term.dispose()
    }
  }, [session.tsid, session.cols, session.rows])

  // 3. Event Loading & Playback Control
  useEffect(() => {
    setLoading(true)
    setPlaying(false)
    playingRef.current  = false
    setElapsed(0)
    elapsedRef.current  = 0
    eventIdxRef.current = 0
    termRef.current?.reset()

    fetchSessionEvents(session.tsid)
      .then(evs => {
        setEvents(evs)
        eventsRef.current = evs
        // Re-fit once data is loaded
        setTimeout(() => fitRef.current?.fit(), 100)

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
        try {
          const raw = atob(ev.data)
          const bytes = new Uint8Array(raw.length)
          for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i)
          termRef.current?.write(bytes)
        } catch (e) { console.error('Failed to decode event data', e) }
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
    termRef.current?.reset()
    play()
  }, [pause, play])

  const seek = useCallback((targetSecs: number) => {
    pause()
    termRef.current?.reset()
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
        try {
          const raw = atob(ev.data)
          const bytes = new Uint8Array(raw.length)
          for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i)
          termRef.current?.write(bytes)
        } catch (e) {}
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

      {/* Terminal Viewport - Pure legacy layout (no CSS scaling, just FitAddon) */}
      <div className="flex-1 overflow-hidden relative flex flex-col items-center justify-center bg-black p-2.5">
         <div ref={containerRef} className="w-full h-full" />
      </div>

      {/* Controls Bar */}
      <div className="bg-surface/95 backdrop-blur-md border-t border-border px-6 py-3 flex items-center gap-4 shadow-md z-40 shrink-0">
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
