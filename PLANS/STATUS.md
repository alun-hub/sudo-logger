# sudo-logger — OSS Improvement Plans

Master tracker. Update status here when a plan (or individual task) is completed.
Each plan file has full detail. This file is the single source of truth for progress.

Last updated: 2026-06-28

---

## Plans

| # | Plan | Status | Notes |
|---|------|--------|-------|
| 01 | [CI/CD & Badges](01-ci-badges.md) | DONE | CI green, codecov active, branch protection enabled |
| 02 | [Test Coverage](02-testing.md) | NOT STARTED | |
| 03 | [Refactoring](03-refactoring.md) | NOT STARTED | |
| 04 | [Releases & Distribution](04-releases-distribution.md) | NOT STARTED | |
| 05 | [Changelog & Versioning](05-changelog-versioning.md) | NOT STARTED | |
| 06 | [Discoverability & Marketing](06-discoverability.md) | NOT STARTED | |
| 07 | [Community Infrastructure](07-community.md) | NOT STARTED | |

---

## Status legend

- `NOT STARTED` — work not yet begun
- `IN PROGRESS` — partially done, see plan file for details
- `DONE` — all tasks completed and verified

---

## Notes for Gemini / Claude

- Read the relevant plan file before starting work on a topic
- Mark individual tasks `[x]` in the plan file as you complete them
- Update the table above when a full plan reaches DONE
- Do not modify task descriptions — only tick boxes and add notes below tasks
- All code changes must pass `pre-commit run --all-files` before committing
- After commits: run `npx gitnexus analyze` to keep the code index fresh
