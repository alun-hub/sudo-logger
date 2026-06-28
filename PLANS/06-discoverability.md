# Plan 06 — Discoverability & Marketing

**Goal:** Reach the first 1 000 GitHub stars and establish sudo-logger as the
de-facto solution for mandatory sudo auditing. The freeze mechanism is the hook.

**Why it matters:** A perfect tool that nobody knows about has zero users. Plans 01-05
build credibility; this plan builds audience.

**Status:** NOT STARTED

---

## Prerequisites before any public launch

All of the following should be done before a public announcement:
- [ ] Plan 01 done (CI badge green)
- [ ] Plan 04 done (binary releases available)
- [ ] Plan 05 done (CHANGELOG.md exists)
- [ ] Demo site (sudo-logger.unixkonsult.se) is live and responsive
- [ ] README has a short screencast or animated GIF showing a session replay

---

## Tasks

### 6.1 — Screencast / demo GIF
The single most effective README addition. People don't read — they watch.

- [ ] Record a 60-90 second terminal session showing:
  1. User runs a sudo command
  2. Replay-server shows the session
  3. Admin replays it in the browser
- [ ] Convert to GIF with `vhs` (https://github.com/charmbracelet/vhs) or `asciinema`
- [ ] If using asciinema: embed the player link, not the raw JSON
- [ ] Add to README immediately after the intro paragraph, before architecture diagram
- [ ] Optional: also record the freeze scenario (server goes down → terminal freezes)

### 6.2 — Rewrite README intro for outsiders
The current intro assumes the reader knows what sudo I/O logging is.

- [ ] First paragraph: the problem (undetected privilege abuse, no mandatory logging)
- [ ] Second paragraph: what sudo-logger does differently (mandatory = freeze)
- [ ] Third paragraph: who should use this (SOC teams, compliance, enterprise Linux)
- [ ] Move technical architecture section below the "Quick start" section

### 6.3 — Hacker News "Show HN"
Timing: do this on a Tuesday or Wednesday, 9-11 AM US Eastern time.

- [ ] Draft post title (try variations):
  - "Show HN: sudo-logger – freeze the terminal if audit logs can't be delivered"
  - "Show HN: Mandatory sudo session recording – terminal freezes if logs aren't ACKed"
- [ ] Draft first comment (post it yourself immediately after submitting):
  - Background: why sudo's built-in logging is optional and easily bypassed
  - The freeze mechanism: how it works, why it matters for compliance
  - Link to demo site
  - Honest limitations section (Linux/RHEL-focused currently)
- [ ] Submit to: https://news.ycombinator.com/submit
- [ ] Monitor comments for 24h and respond promptly

### 6.4 — Reddit posts
After HN (or same week if HN doesn't get traction):

- [ ] r/sysadmin — "We built mandatory sudo session logging: if the log server is
  unreachable, sudo freezes. Looking for feedback."
- [ ] r/netsec — Focus on the compliance + audit integrity angle
- [ ] r/linux — More technical, focus on the sudo plugin API approach
- [ ] r/devops — Focus on the Kubernetes/enterprise deployment story

Rules: be transparent that you built it, be genuinely helpful in comments, don't
spam multiple subs on the same day.

### 6.5 — Blog post: "Why sudo logging is broken by default"
- [ ] Write a 1000-1500 word post explaining:
  1. What `sudo` logs by default (not much)
  2. What `sudo_logsrvd` offers and why it's not mandatory
  3. How an attacker bypasses optional logging
  4. How mandatory ACK + freeze closes that gap
  5. sudo-logger demo
- [ ] Publish on: dev.to (free, good SEO) AND link from project README
- [ ] Cross-post to LinkedIn article
- [ ] Add to `docs/` as `why-mandatory-logging.md` (long-term reference)

### 6.6 — Comparison page
- [ ] Create `docs/comparison.md` comparing sudo-logger vs:
  - `sudo_logsrvd` (built-in, no mandatory ACK)
  - `auditd` (kernel-level, different scope)
  - BeyondTrust / CyberArk (enterprise PAM, different price point)
- [ ] Be factual and honest — note where others are better
- [ ] Link from README under "Why sudo-logger?"

### 6.7 — SIEM integration blog / tutorial
- [ ] Write a short tutorial: "Shipping sudo-logger events to Elastic/Opensearch"
- [ ] Include: sample index template, Kibana dashboard JSON (export from demo)
- [ ] Publish dashboard JSON under `contrib/elastic/` in the repo
- [ ] This will be found by people searching for "sudo audit elastic" etc.

### 6.8 — GitHub topic tags
- [ ] Add topics to the GitHub repo (repo settings → Topics):
  `sudo`, `audit`, `security`, `logging`, `linux`, `compliance`, `golang`,
  `session-recording`, `privileged-access`, `siem`
- [ ] These improve GitHub search discoverability significantly

### 6.9 — Helm chart on Artifact Hub (stretch goal)
- [ ] The `k8s/` directory already exists — package as a Helm chart
- [ ] Publish to Artifact Hub: https://artifacthub.io
- [ ] Artifact Hub has a dedicated audience of Kubernetes operators
- [ ] Add `artifacthub.io/category: security` annotation

---

## Files to create / modify

| File | Action |
|------|--------|
| `README.md` | MODIFY — rewrite intro, add GIF, add comparison link |
| `docs/why-mandatory-logging.md` | CREATE |
| `docs/comparison.md` | CREATE (already exists partially as comparison-sudo-logsrvd.md — expand) |
| `contrib/elastic/dashboard.json` | CREATE |
| `contrib/elastic/index-template.json` | CREATE |
| `charts/` | MODIFY — add artifacthub metadata |

---

## Definition of done

- Show HN posted with >50 points (aim, not guaranteed)
- Blog post published on dev.to with >500 views within 2 weeks
- GitHub stars > 200 within 1 month of launch
- README has a working screencast/GIF
- Repo has 8+ GitHub topic tags
