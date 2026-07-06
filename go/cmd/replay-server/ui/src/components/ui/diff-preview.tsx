import type { LineDiff } from '@/lib/diff'

const MAX_LINES_SHOWN = 8

/**
 * DiffPreview renders a compact, git-style +/- line list for a LineDiff —
 * used in confirmation dialogs before a sudoers/sandbox config push so an
 * admin sees roughly what's about to change, not just a bare "confirm?".
 */
export function DiffPreview({ diff }: { diff: LineDiff }) {
  if (diff.added.length === 0 && diff.removed.length === 0) {
    return (
      <div className="mt-2 px-2 py-1.5 rounded-[4px] border border-border bg-bg text-[11px] text-text-dim italic">
        No line-level changes detected.
      </div>
    )
  }

  return (
    <div className="mt-2 max-h-48 overflow-y-auto rounded-[4px] border border-border bg-bg font-mono text-[11px]">
      {diff.removed.slice(0, MAX_LINES_SHOWN).map((line, i) => (
        <div key={`r${i}`} className="px-2 py-0.5 text-red bg-red/5 truncate">
          − {line || '(blank line)'}
        </div>
      ))}
      {diff.removed.length > MAX_LINES_SHOWN && (
        <div className="px-2 py-0.5 text-text-dim">…and {diff.removed.length - MAX_LINES_SHOWN} more removed</div>
      )}
      {diff.added.slice(0, MAX_LINES_SHOWN).map((line, i) => (
        <div key={`a${i}`} className="px-2 py-0.5 text-green bg-green/5 truncate">
          + {line || '(blank line)'}
        </div>
      ))}
      {diff.added.length > MAX_LINES_SHOWN && (
        <div className="px-2 py-0.5 text-text-dim">…and {diff.added.length - MAX_LINES_SHOWN} more added</div>
      )}
    </div>
  )
}
