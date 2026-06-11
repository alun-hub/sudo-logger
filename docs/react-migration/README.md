# React Migration — Task Index

Migrate the replay-server UI from a 347KB vanilla JS `index.html` to a
React + TypeScript SPA (Vite, shadcn/ui, Tailwind v4, @xterm/xterm).

## Stack
Vite · React 19 · TypeScript 5 · Tailwind v4 · shadcn/ui · React Router v6 ·
TanStack Query v5 · @xterm/xterm · Vitest + RTL

## Tasks (run in order)

| # | File | What it does | Produces |
|---|------|-------------|---------|
| 01 | [task-01-project-setup.md](task-01-project-setup.md) | Vite project scaffold, deps, vite.config.ts, Tailwind, shadcn/ui init | `ui/` project, empty App |
| 02 | [task-02-api-layer.md](task-02-api-layer.md) | Typed API client + all TypeScript types | `src/api/`, `src/types/`, `src/lib/` |
| 03 | [task-03-appshell-sessions.md](task-03-appshell-sessions.md) | AppShell + Sessions view (session list + xterm terminal replay) | Working Sessions tab |
| 04 | [task-04-reports-policy.md](task-04-reports-policy.md) | Reports view + Policy editor (YAML rules, user lists) | Reports + Policy tabs |
| 05 | [task-05-config-approvals.md](task-05-config-approvals.md) | Config panel (SIEM/Auth/Users/Retention/Sandbox/JIT) + Approvals view | Config + Approvals tabs |
| 06 | [task-06-go-integration-cleanup.md](task-06-go-integration-cleanup.md) | SPA fallback in Go, Makefile update, cleanup old static/, RPM build | Deployable binary |

## Key constraints
- Build output goes to `go/cmd/replay-server/static/` (Go embeds this dir)
- Do NOT commit `static/` — it is generated
- All dates formatted as `yyyy-mm-dd HH:mm` (24h)
- Run `pre-commit run --all-files` before committing
- Fix all HIGH/CRITICAL Trivy findings before committing
