import { useEffect, useRef, useState, useCallback } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { fetchSessionEvents } from '@/api/sessions'
import { fmtDuration } from '@/lib/date'
import { Button } from '@/components/ui/button'
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
      theme: { background: '#18181b', foreground: '#e4e4e7' },
      fontSize: 13,
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
      cursorBlink: false,
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
      if ((ev.type === 'o' || ev.type === 'i') && ev.data) {
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
      if ((ev.type === 'o' || ev.type === 'i') && ev.data) {
        termRef.current?.write(atob(ev.data))
      }
    }
  }, [pause])

  const totalDuration = events.length > 0 ? events[events.length - 1].t : session.duration

  return (
    <div className="flex flex-col h-full bg-zinc-900 text-zinc-100">
      <div ref={containerRef} className="flex-1 overflow-hidden p-1" />
      <div className="flex items-center gap-2 px-3 py-2 border-t border-zinc-700 text-sm shrink-0">
        {loading ? (
          <span className="text-zinc-400 text-xs">Loading events…</span>
        ) : (
          <>
            <Button size="sm" variant="ghost" onClick={restart}
              className="text-zinc-300 h-7 px-2 hover:bg-zinc-700">↩</Button>
            <Button size="sm" variant="ghost" onClick={playing ? pause : play}
              className="text-zinc-300 h-7 px-2 hover:bg-zinc-700">
              {playing ? '⏸' : '▶'}
            </Button>
            <input
              type="range"
              min={0}
              max={totalDuration}
              step={0.1}
              value={elapsed}
              onChange={e => seek(Number(e.target.value))}
              className="flex-1 h-1 accent-zinc-300"
            />
            <span className="text-zinc-400 font-mono text-xs w-28 text-right">
              {fmtDuration(elapsed)} / {fmtDuration(totalDuration)}
            </span>
            <select
              value={speed}
              onChange={e => {
                speedRef.current = Number(e.target.value)
                setSpeed(Number(e.target.value))
              }}
              className="bg-zinc-800 text-zinc-300 text-xs rounded px-1 h-7 border border-zinc-700"
            >
              {[0.25, 0.5, 1, 2, 5, 10].map(s => (
                <option key={s} value={s}>{s}×</option>
              ))}
            </select>
          </>
        )}
      </div>
    </div>
  )
}
