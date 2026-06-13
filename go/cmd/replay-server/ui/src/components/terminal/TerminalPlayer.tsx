import { useEffect, useRef, useState } from 'react'
import * as AsciinemaPlayer from 'asciinema-player'
import 'asciinema-player/dist/bundle/asciinema-player.css'
import { RiskBadge } from '../sessions/RiskBadge'
import type { SessionInfo } from '@/types/session'

interface Props {
  session: SessionInfo
}

function detectDimensions(castData: string): { cols: number, rows: number } {
  let cols = 80;
  let rows = 24;

  // Match CUP (Cursor Position) and HVP (Horizontal and Vertical Position)
  // e.g. \x1b[24;80H
  const reCUP = /(?:\\u001b|\\x1b|\x1b)\[(\d+);(\d+)[Hf]/gi;
  let match;
  while ((match = reCUP.exec(castData)) !== null) {
    const r = parseInt(match[1], 10);
    const c = parseInt(match[2], 10);
    if (r > rows) rows = r;
    if (c > cols) cols = c;
  }

  // Match VPA (Line Position Absolute)
  const reVPA = /(?:\\u001b|\\x1b|\x1b)\[(\d+)d/gi;
  while ((match = reVPA.exec(castData)) !== null) {
    const r = parseInt(match[1], 10);
    if (r > rows) rows = r;
  }

  // Match CHA (Cursor Character Absolute)
  const reCHA = /(?:\\u001b|\\x1b|\x1b)\[(\d+)G/gi;
  while ((match = reCHA.exec(castData)) !== null) {
    const c = parseInt(match[1], 10);
    if (c > cols) cols = c;
  }

  // Cap at reasonable max bounds so malformed ANSI doesn't crash the browser
  return {
    cols: Math.min(cols, 500),
    rows: Math.min(rows, 150)
  };
}

export function TerminalPlayer({ session }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const playerRef = useRef<any>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const el = containerRef.current as HTMLElement | null;
    if (!el) return;

    let blobUrl: string | null = null;
    let isMounted = true;

    async function initPlayer() {
      try {
        const res = await fetch(`/api/session/cast?tsid=${encodeURIComponent(session.tsid)}`);
        if (!res.ok) throw new Error(`Failed to fetch cast data: ${res.status}`);
        const text = await res.text();

        if (!isMounted) return;

        // Find the absolute maximum grid size required by the app (vi/ncurses)
        const { cols, rows } = detectDimensions(text);

        // Rewrite the asciicast header in-memory
        const lines = text.split('\n');
        if (lines.length > 0 && lines[0].startsWith('{')) {
          try {
            const header = JSON.parse(lines[0]);
            header.width = cols;
            header.height = rows;
            lines[0] = JSON.stringify(header);
          } catch (e) {
            console.error('Failed to parse cast header', e);
          }
        }

        const modifiedText = lines.join('\n');
        const blob = new Blob([modifiedText], { type: 'application/x-ndjson' });
        blobUrl = URL.createObjectURL(blob);

        if (playerRef.current) {
          playerRef.current.dispose();
        }

        playerRef.current = AsciinemaPlayer.create(blobUrl, el as HTMLElement, {
          autoPlay: localStorage.getItem('sudo-replay-autoplay') !== 'false',
          speed: 1.0,
          idleTimeLimit: 2,
          theme: 'asciinema',
          terminalFontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
          terminalLineHeight: 1.3,
          fit: 'both', // Scale the player so the detected grid fits perfectly on screen
        });
      } catch (e: any) {
         if (isMounted) setError(e.message);
      }
    }

    initPlayer();

    return () => {
      isMounted = false;
      if (playerRef.current) {
        playerRef.current.dispose()
        playerRef.current = null
      }
      if (blobUrl) {
        URL.revokeObjectURL(blobUrl)
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
         {error ? (
            <div className="text-red-400 font-mono text-sm p-4">{error}</div>
         ) : (
            <div ref={containerRef} className="absolute inset-0 flex items-center justify-center p-4 w-full h-full" />
         )}
      </div>
    </div>
  )
}
