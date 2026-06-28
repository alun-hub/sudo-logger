# Plan 04 — Releases & Distribution

**Goal:** Anyone on any Linux distribution can install sudo-logger in under 5 minutes
without building from source. Releases are signed and verifiable.

**Current state:** RPM only, built manually with a helper script. No binary releases on
GitHub. Blocks adoption on Debian/Ubuntu (the majority of Linux servers).

**Status:** NOT STARTED

---

## Tasks

### 4.1 — goreleaser setup
goreleaser automates building multi-arch binaries and publishing GitHub Releases.

- [ ] Install goreleaser locally: `go install github.com/goreleaser/goreleaser/v2@latest`
- [ ] Run `goreleaser init` in project root to generate `.goreleaser.yaml`
- [ ] Configure builds for:
  - `cmd/agent` → binary `sudo-logger-agent`
  - `cmd/server` → binary `sudo-logger-server`
  - `cmd/replay-server` → binary `sudo-logger-replay`
- [ ] Target platforms: `linux/amd64`, `linux/arm64`
- [ ] Configure archives: `.tar.gz` with binary + default config files
- [ ] Add `goreleaser check` step to CI (lints the config)
- [ ] Test locally with `goreleaser release --snapshot --clean`

### 4.2 — Signed releases with cosign (Sigstore)
Critical for a security tool. Sysadmins will not install unsigned audit software.

- [ ] Install cosign: `go install github.com/sigstore/cosign/v2/cmd/cosign@latest`
- [ ] Add cosign signing step to goreleaser config:
  ```yaml
  signs:
    - cmd: cosign
      args:
        - sign-blob
        - --output-signature=${signature}
        - ${artifact}
      artifacts: all
  ```
- [ ] Use keyless signing (OIDC-based, no key to manage) with GitHub Actions OIDC
- [ ] Add verification instructions to INSTALLATION.md:
  ```bash
  cosign verify-blob \
    --bundle sudo-logger-agent-linux-amd64.tar.gz.bundle \
    sudo-logger-agent-linux-amd64.tar.gz
  ```
- [ ] Test that a release can be verified after signing

### 4.3 — GitHub Actions release workflow
- [ ] Create `.github/workflows/release.yml`
- [ ] Trigger on: push of a tag matching `v*.*.*`
- [ ] Steps:
  1. Checkout with full history (`fetch-depth: 0`) — goreleaser needs git tags
  2. Setup Go
  3. Install cosign
  4. Run `goreleaser release --clean`
  5. Publish to GitHub Releases automatically
- [ ] Set `GITHUB_TOKEN` permissions: `contents: write`
- [ ] Test with a pre-release tag (`v0.0.1-test`) before a real release

### 4.4 — Debian/Ubuntu packages (.deb)
- [ ] Use `nfpm` (included in goreleaser) to build `.deb` alongside `.rpm`
- [ ] Add `nfpm.yaml` or inline config in `.goreleaser.yaml` for:
  - Package name: `sudo-logger-client`, `sudo-logger-server`, `sudo-logger-replay`
  - Dependencies: `sudo` (client), `postgresql-client` (server optional)
  - Systemd service files: include existing `.service` files
  - Post-install script: `systemctl daemon-reload && systemctl enable sudo-logger-agent`
- [ ] Test `.deb` install on Ubuntu 22.04 (Docker container is fine)
- [ ] Add `.deb` to GitHub Release artifacts

### 4.5 — One-liner install script
- [ ] Create `scripts/install.sh`:
  - Detect distro (rpm-based vs deb-based)
  - Detect arch (amd64/arm64)
  - Download latest release from GitHub API
  - Verify cosign signature before installing
  - Install the binary + service file
  - Print next-steps (configure `/etc/sudo-logger/agent.conf`)
- [ ] Host script at a stable URL (GitHub raw or docs site)
- [ ] Document in README: `curl -sSL https://raw.githubusercontent.com/alun-hub/sudo-logger/main/scripts/install.sh | bash`
- [ ] Test on: Fedora, Ubuntu, Rocky Linux, Debian

### 4.6 — Ansible role (stretch goal)
- [ ] Create `contrib/ansible/roles/sudo-logger-client/`
  - `tasks/main.yml` — install package, configure, enable service
  - `defaults/main.yml` — server_host, server_port, tls_cert_path
  - `handlers/main.yml` — restart agent on config change
  - `README.md` — usage example
- [ ] Publish to Ansible Galaxy: `ansible-galaxy role import alun-hub sudo-logger`
- [ ] Link from README under "Installation"

---

## Files to create / modify

| File | Action |
|------|--------|
| `.goreleaser.yaml` | CREATE |
| `.github/workflows/release.yml` | CREATE |
| `nfpm.yaml` (or inline) | CREATE |
| `scripts/install.sh` | CREATE |
| `INSTALLATION.md` | MODIFY — add binary install + cosign verification |
| `README.md` | MODIFY — add one-liner install |
| `contrib/ansible/` | CREATE (stretch goal) |

---

## Definition of done

- `v1.x.x` tag triggers automated build + publish to GitHub Releases
- GitHub Releases page shows: `.tar.gz`, `.rpm`, `.deb` for amd64 + arm64 with cosign bundles
- `scripts/install.sh` works on Fedora 44, Ubuntu 24.04, Rocky Linux 9
- INSTALLATION.md documents signature verification
- Ansible role published on Galaxy (stretch goal)
