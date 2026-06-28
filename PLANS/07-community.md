# Plan 07 — Community Infrastructure

**Goal:** Create the infrastructure for contributors and users to ask questions, report
issues, and discuss the project — lowering the barrier from "interested" to "contributor."

**Why it matters:** A project with no community channel signals that questions go
unanswered. This is the #1 reason people don't adopt otherwise-good OSS tools.

**Status:** NOT STARTED

---

## Tasks

### 7.1 — GitHub Discussions
Easiest first step — zero setup cost, lives inside GitHub.

- [ ] Enable GitHub Discussions (repo → Settings → Features → Discussions ✓)
- [ ] Create starter categories:
  - **Q&A** — questions about installation, configuration, troubleshooting
  - **Ideas** — feature requests and proposals
  - **Show & Tell** — users sharing their deployments
  - **Announcements** — pinned, only maintainer posts (releases, blog posts)
- [ ] Pin a welcome post: "Welcome — read this before posting"
  - Links to INSTALLATION.md, CONTRIBUTING.md, known limitations
- [ ] Update README to link to Discussions for support

### 7.2 — Discord server
For real-time chat. Discord is the dominant choice for OSS technical communities in 2026.

- [ ] Create a Discord server named "sudo-logger"
- [ ] Channels:
  - `#announcements` (read-only, maintainer posts)
  - `#general` (general discussion)
  - `#help` (installation / configuration questions)
  - `#dev` (development discussion, PRs, ideas)
  - `#security` (security findings — note this is NOT for reports, see CONTRIBUTING)
- [ ] Add a bot: Combot or MEE6 for basic moderation (spam filter, welcome message)
- [ ] Welcome message should link: docs, CONTRIBUTING.md, GitHub Discussions
- [ ] Get a stable Discord invite link (set expiry to "never")
- [ ] Add Discord badge + link to README
- [ ] Add Discord link to CONTRIBUTING.md under "Getting help"

### 7.3 — Issue triage process
The current issue templates are good. Add a lightweight triage process:

- [ ] Add GitHub issue labels:
  - `good first issue` — small, well-defined, no deep knowledge needed
  - `help wanted` — good for external contributors
  - `bug`, `enhancement`, `security`, `documentation`, `question`
  - `distro:rpm`, `distro:deb` — for platform-specific issues
- [ ] Mark 3-5 existing issues or create new ones as `good first issue`
  - Examples: "Add test for X", "Document Y", "Add --version flag"
- [ ] Add a "Good first issues" section to CONTRIBUTING.md with a link to the label filter

### 7.4 — Response time commitment
Document in CONTRIBUTING.md:

```markdown
## Maintainer response time

This is a solo-maintained project. I aim to:
- Respond to bug reports within **5 business days**
- Review pull requests within **10 business days**
- Acknowledge security reports within **48 hours**

If you haven't heard back, feel free to ping in Discord or comment on the issue.
```

- [ ] Add this section to CONTRIBUTING.md
- [ ] This sets expectations and prevents users from assuming abandonment

### 7.5 — Security reporting process
The project already mentions private vulnerability reporting in CONTRIBUTING.md. Verify:

- [ ] GitHub private security advisories are enabled (repo → Security → Advisories)
- [ ] SECURITY.md exists with:
  - How to report (private advisory URL)
  - What to include (steps to reproduce, impact)
  - Response time commitment (48h acknowledgement)
  - Disclosure policy (coordinated disclosure, 90-day default)
- [ ] Link SECURITY.md from README security section

### 7.6 — Contributor recognition
Small things that make contributors feel valued:

- [ ] Add `CONTRIBUTORS.md` — list of people who have contributed (start with yourself)
- [ ] Use `@all-contributors` bot (allcontributors.org) to automate this
  - Tracks: code, docs, bug reports, ideas, design
  - Run: `@all-contributors please add @username for code`
- [ ] Add a "Contributors" section to README with the generated table

### 7.7 — Office hours (stretch goal)
Once there are regular Discord users:

- [ ] Schedule a monthly 30-minute open video call (Google Meet / Jitsi)
  - "Ask me anything about sudo-logger"
  - Share screen, answer questions live
- [ ] Announce in Discord + GitHub Discussions
- [ ] Record and post to YouTube (creates discoverable content over time)

---

## Files to create / modify

| File | Action |
|------|--------|
| `SECURITY.md` | CREATE |
| `CONTRIBUTORS.md` | CREATE |
| `CONTRIBUTING.md` | MODIFY — add response times, Discord link, good first issues |
| `README.md` | MODIFY — add Discord badge, Discussions link, Contributors section |

---

## Definition of done

- GitHub Discussions enabled with 4 categories and a pinned welcome post
- Discord server live with stable invite link and welcome bot configured
- 5+ issues labelled `good first issue`
- SECURITY.md exists and is linked from README
- CONTRIBUTING.md documents response times and how to get help
- Discord badge visible in README
