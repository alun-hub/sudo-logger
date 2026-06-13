import { useEffect, useRef, useState } from 'react'
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
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!containerRef.current) return
    let blobUrl: string | null = null;
    let isMounted = true;

    async function initPlayer() {
      try {
        const res = await fetch(`/api/session/cast?tsid=${encodeURIComponent(session.tsid)}`);
        if (!res.ok) throw new Error(`Failed to fetch cast data: ${res.status}`);
        const text = await res.text();

        if (!isMounted) return;

        // DYNAMIC SIZING: Mimic legacy SPA and native CLI behavior
        // Instead of guessing dimensions from ANSI, we calculate how many characters
        // can physically fit inside the current browser container. This prevents
        // asciinema-player from word-wrapping (which destroys vi/ncurses) or
        // scaling the font out of proportion.
        const rect = containerRef.current!.getBoundingClientRect();

        // Approximate character sizes for 14px monospace font
        const charWidth = 8.4;
        const charHeight = 18.2; // 14px * 1.3 line-height

        // Subtract a small margin (10px) to ensure no scrollbars appear
        const dynamicCols = Math.max(80, Math.floor((rect.width - 10) / charWidth));
        const dynamicRows = Math.max(24, Math.floor((rect.height - 10) / charHeight));

        // Rewrite the header line to inject our calculated true-to-viewport dimensions
        const lines = text.split('\n');
        if (lines.length > 0 && lines[0].startsWith('{')) {
          try {
            const header = JSON.parse(lines[0]);
            header.width = dynamicCols;
            header.height = dynamicRows;
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

        playerRef.current = AsciinemaPlayer.create(blobUrl, containerRef.current!, {
          autoPlay: localStorage.getItem('sudo-replay-autoplay') !== 'false',
          speed: 1.0,
          idleTimeLimit: 2,
          theme: 'asciinema',
          terminalFontSize: '14px',
          terminalFontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace",
          terminalLineHeight: 1.3,
          fit: false, // Turn off automatic scaling! Render 1:1 crisp pixels using our calculated grid.
        });
      } catch (e: any) {
         if (isMounted) setError(e.message);
      }
    }

    initPlayer();

    // Handle window resize by re-initializing the player (simple debounce)
    let resizeTimer: any;
    const handleResize = () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        if (isMounted) initPlayer();
      }, 300);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      isMounted = false;
      window.removeEventListener('resize', handleResize);
      clearTimeout(resizeTimer);
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
      <div className="flex-1 overflow-hidden relative bg-black flex items-center justify-center p-4">
         {error ? (
            <div className="text-red-400 font-mono text-sm">{error}</div>
         ) : (
            <div ref={containerRef} className="w-full h-full" />
         )}
      </div>
    </div>
  )
}
