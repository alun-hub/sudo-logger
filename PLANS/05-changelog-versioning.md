# Plan 05 — Changelog & Versioning

**Goal:** Every release has a readable, standardised changelog. Semantic versioning is
enforced. Users can understand what changed and whether to upgrade.

**Current state:** No CHANGELOG.md. Version bumps tracked only in RPM spec files.
No semver policy documented.

**Why it matters:** "Is this project maintained?" is answered in 3 seconds by looking at
the changelog. A missing changelog signals abandonment.

**Status:** NOT STARTED

---

## Tasks

### 5.1 — Write CHANGELOG.md from git history
- [ ] Install `git-cliff`: `cargo install git-cliff` or download binary from GitHub
- [ ] Run `git-cliff --output CHANGELOG.md` to auto-generate from commit history
- [ ] Review and clean up the generated output — remove noise, fix descriptions
- [ ] Structure: newest release at top, each entry with sections:
  ```
  ## [1.20.27] - 2026-06-xx
  ### Added
  - ...
  ### Fixed
  - ...
  ### Changed
  - ...
  ```
- [ ] Go back to at least v1.18.0 or the first "public" release
- [ ] Commit the CHANGELOG.md to main

### 5.2 — Configure git-cliff for future releases
- [ ] Create `cliff.toml` in project root
- [ ] Configure commit types to sections:
  - `feat` → Added
  - `fix` → Fixed
  - `refactor` → Changed
  - `docs` → Documentation
  - `chore` → Internal (hidden from changelog unless significant)
  - `security` → Security (always shown, highlighted)
- [ ] Add `git-cliff --bump` step to release process so changelog updates automatically
  on each tag
- [ ] Document the process in CONTRIBUTING.md:
  > When releasing: `git-cliff --bump --output CHANGELOG.md && git commit -am "chore: update changelog" && git tag vX.Y.Z`

### 5.3 — Document semver policy
Add a section to CONTRIBUTING.md:

```markdown
## Versioning

sudo-logger follows [Semantic Versioning](https://semver.org).

| Change type | Version bump | Example |
|---|---|---|
| Breaking wire protocol change | MAJOR | 1.x.x → 2.0.0 |
| New feature, backwards-compatible | MINOR | 1.20.x → 1.21.0 |
| Bug fix, no API/protocol change | PATCH | 1.20.27 → 1.20.28 |

The plugin.so and agent must always be compatible within the same MAJOR version.
```

- [ ] Add versioning section to CONTRIBUTING.md
- [ ] Verify current version numbering is consistent with this policy
  (currently at v1.20.x — check if any past bumps violated semver)

### 5.4 — Version in Go code
- [ ] Confirm there is a canonical version string in the codebase (e.g., `cmd/agent/version.go`)
- [ ] If not: create `go/internal/version/version.go` with `var Version = "dev"`
- [ ] Wire goreleaser ldflags to inject version at build time:
  ```yaml
  # in .goreleaser.yaml
  builds:
    - ldflags:
        - -X sudo-logger/internal/version.Version={{.Version}}
  ```
- [ ] Ensure `--version` flag works on agent, server, and replay-server
- [ ] Add version to log output on startup (already common practice)

### 5.5 — GitHub Release notes template
- [ ] Create `.github/release.yml` to categorise PRs/commits in GitHub's auto-generated
  release notes (complementary to CHANGELOG.md):
  ```yaml
  changelog:
    categories:
      - title: "New Features"
        labels: ["enhancement"]
      - title: "Bug Fixes"
        labels: ["bug"]
      - title: "Security"
        labels: ["security"]
  ```

---

## Files to create / modify

| File | Action |
|------|--------|
| `CHANGELOG.md` | CREATE |
| `cliff.toml` | CREATE |
| `CONTRIBUTING.md` | MODIFY — add versioning section + release process |
| `go/internal/version/version.go` | CREATE (if not exists) |
| `.github/release.yml` | CREATE |

---

## Definition of done

- `CHANGELOG.md` exists with entries back to at least v1.18.0
- `git-cliff --bump` generates correct next-version entry
- `sudo-logger-agent --version` prints the version string
- CONTRIBUTING.md documents the release process step by step
- GitHub Releases show categorised changelogs
