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
        // auto play if checked in top bar? we'll just play automatically for now to match old behavior
        setTimeout(() => play(), 100)
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
  const fillPct = totalDuration > 0 ? Math.min(100, Math.max(0, (elapsed / totalDuration) * 100)) : 0

  return (
    <div className="flex flex-col h-full bg-[#09090f]">
      {/* Top Session Header */}
      <div className="h-[44px] flex items-center px-4 border-b border-[#1e2230] bg-[#0f1117] shrink-0 text-[13px] font-mono text-[#d4daf0]">
        <span className="text-[#00e87a] mr-2">{session.user}@{session.host}</span>
        <span className="text-[#4a5068] mr-2">—</span>
        <span className="text-[#8890a8] mr-2">{session.runas}</span>
        <span className="text-[#4a5068] mr-2">—</span>
        <span className="truncate">{session.command}</span>
      </div>

      {/* Terminal Viewport */}
      <div ref={containerRef} className="flex-1 overflow-hidden p-2.5" />

      {/* Controls Bar */}
      <div className="flex items-center gap-[10px] px-4 py-2.5 bg-[#0f1117] border-t border-[#1e2230] shrink-0">
        <button
          onClick={restart}
          disabled={loading || events.length === 0}
          className="w-[30px] h-[30px] flex items-center justify-center rounded-[5px] bg-[#161921] border border-[#1e2230] text-[#8890a8] hover:bg-[#1c1f2e] hover:text-[#d4daf0] disabled:opacity-35 disabled:cursor-not-allowed transition-colors shrink-0"
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/></svg>
        </button>

        <button
          onClick={playing ? pause : play}
          disabled={loading || events.length === 0}
          className="w-[34px] h-[30px] flex items-center justify-center rounded-[5px] bg-[#003d20] border border-[#00e87a] text-[#00e87a] hover:bg-[#00e87a]/25 disabled:opacity-35 disabled:cursor-not-allowed transition-colors shrink-0"
        >
          {playing ? (
             <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>
          ) : (
             <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>
          )}
        </button>

        <div className="text-[12px] text-[#00e87a] min-w-[36px] text-center font-mono shrink-0">
          {fmtDuration(elapsed)}
        </div>

        <div className="flex-1 flex items-center px-2">
          <input
            type="range"
            min={0}
            max={totalDuration}
            step={0.1}
            value={elapsed}
            onChange={e => seek(Number(e.target.value))}
            disabled={loading || events.length === 0}
            className="w-full h-[3px] rounded-[2px] outline-none cursor-pointer appearance-none"
            style={{
              background: `linear-gradient(to right, #00e87a 0%, #00e87a ${fillPct}%, #2a2f42 ${fillPct}%, #2a2f42 100%)`
            }}
          />
        </div>

        <div className="text-[12px] text-[#8890a8] min-w-[36px] text-center font-mono shrink-0">
          {fmtDuration(totalDuration)}
        </div>

        <select
          value={speed}
          onChange={e => {
            speedRef.current = Number(e.target.value)
            setSpeed(Number(e.target.value))
          }}
          disabled={loading || events.length === 0}
          className="bg-transparent text-[#8890a8] font-mono text-[12px] h-[30px] outline-none cursor-pointer border-none"
        >
          {[0.25, 0.5, 1, 1.5, 2, 4, 8, 16].map(s => (
            <option key={s} value={s} className="bg-[#161921]">{s}x</option>
          ))}
        </select>

        {loading && <span className="text-[12px] text-[#8890a8] ml-2 animate-pulse">Loading...</span>}
      </div>
    </div>
  )
}
