# Plan 01 — CI/CD & Badges

**Goal:** Every visitor to the GitHub repo sees a green CI badge and knows the project is
actively maintained and tested. codecov shows coverage trends over time.

**Why it matters:** A project without CI signals "hobby project." Badges are the first
thing experienced contributors check before deciding to engage.

**Status:** IN PROGRESS

---

## Tasks

### 1.1 — Go test workflow
- [x] Create `.github/workflows/test.yml`
- [x] Trigger on: push to main, all pull_requests
- [x] Matrix: Go 1.25.x and stable (matched to go.mod requirement)
- [x] Steps: checkout → setup-go → go build → go test -race -coverprofile → codecov upload
- [ ] Verify the workflow runs green on main after push

### 1.2 — Pre-commit / lint workflow
- [x] Create `.github/workflows/lint.yml`
- [x] Trigger on: push to main, pull_requests
- [x] Four jobs: golangci-lint, trivy, C plugin (cppcheck+flawfinder), pre-commit general hooks
- Note: pre-commit system hooks (go-vet, go-test, trivy, cppcheck, flawfinder) are SKIPPED
  in CI via SKIP= env var and replaced by dedicated jobs — avoids hardcoded GOROOT=/usr/lib/golang
  path that only works locally.

### 1.3 — codecov integration
- [ ] MANUAL: Sign up at codecov.io and link the alun-hub/sudo-logger repo
- [ ] MANUAL: Add `CODECOV_TOKEN` as a GitHub Actions secret (repo Settings → Secrets → Actions)
- [ ] MANUAL: Verify coverage report appears after first CI run
- [ ] MANUAL: Set coverage target threshold of 40% in codecov.io settings

### 1.4 — Badges in README
- [x] Added all 5 badges to README.md (CI, codecov, Go Report Card, License, Latest Release)
- [ ] MANUAL: Visit https://goreportcard.com/report/github.com/alun-hub/sudo-logger to trigger first scan
- [ ] MANUAL: Verify badges render correctly on GitHub after push

### 1.5 — Branch protection
- [ ] MANUAL: GitHub repo Settings → Branches → Add branch protection rule for `main`
  - Enable: "Require status checks to pass before merging"
  - Required checks: `test (1.25.x, ubuntu-24.04)`, `test (stable, ubuntu-24.04)`, `golangci-lint`, `trivy`

---

## Files to create / modify

| File | Action |
|------|--------|
| `.github/workflows/test.yml` | CREATE |
| `.github/workflows/lint.yml` | CREATE |
| `README.md` | MODIFY — add badges section |

---

## Definition of done

- Green CI badge visible on GitHub repo front page
- codecov.io showing coverage graph for main branch
- Go Report Card showing a grade
- `pre-commit` failures block merges
