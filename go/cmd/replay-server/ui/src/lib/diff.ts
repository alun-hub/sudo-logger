export interface LineDiff {
  added: string[]
  removed: string[]
}

/**
 * summarizeLineDiff returns the lines present in newContent but not
 * oldContent (added) and vice versa (removed) — a coarse, dependency-free
 * line-set diff, not a real LCS-based diff. Mirrors the same algorithm as
 * the backend's summarizeLineDiff (go/cmd/replay-server/handlers_admin_config.go)
 * so the confirmation dialog shown before a push roughly matches what gets
 * logged/audited server-side.
 */
export function summarizeLineDiff(oldContent: string, newContent: string): LineDiff {
  const count = (s: string): Map<string, number> => {
    const m = new Map<string, number>()
    if (!s) return m
    const trimmed = s.endsWith('\n') ? s.slice(0, -1) : s
    for (const line of trimmed.split('\n')) {
      m.set(line, (m.get(line) ?? 0) + 1)
    }
    return m
  }
  const oldLines = count(oldContent)
  const newLines = count(newContent)
  const added: string[] = []
  const removed: string[] = []
  for (const [line, n] of newLines) {
    const d = n - (oldLines.get(line) ?? 0)
    for (let i = 0; i < d; i++) added.push(line)
  }
  for (const [line, n] of oldLines) {
    const d = n - (newLines.get(line) ?? 0)
    for (let i = 0; i < d; i++) removed.push(line)
  }
  return { added, removed }
}
