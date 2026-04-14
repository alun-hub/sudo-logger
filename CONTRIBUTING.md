# Contributing to sudo-logger

Thank you for your interest in contributing to sudo-logger. This document describes how to get started, what to expect, and how to report security issues.

## Reporting Security Vulnerabilities

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security vulnerabilities by emailing the maintainer directly (see the GitHub profile) or by using [GitHub's private vulnerability reporting](https://github.com/alun-hub/sudo-logger/security/advisories/new). Include a description of the issue, steps to reproduce, and potential impact.

## Getting Started

### Prerequisites

- Go 1.22+
- `pre-commit` (install with `pip install pre-commit`)
- `rpmbuild` (optional, for RPM packaging)
- A running PostgreSQL instance (optional, for distributed mode)

### Development setup

```bash
git clone https://github.com/alun-hub/sudo-logger.git
cd sudo-logger
pre-commit install
cd go && go build ./...
```

### Running tests

```bash
cd go && go test ./...
```

## Making Changes

1. **Fork** the repository and create a branch from `main`.
2. **Run impact analysis** before editing any function — see `CLAUDE.md` for details.
3. **Write tests** for new behavior where practical.
4. **Run pre-commit** before pushing:
   ```bash
   pre-commit run --all-files
   ```
   All checks must pass, including Trivy and Semgrep. Fix any HIGH or CRITICAL findings.
5. **Open a pull request** against `main`.

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`).
- Keep functions small and focused.
- Document exported symbols in English.
- Do not add error handling for scenarios that cannot happen.

## Commit Messages

Use the conventional commits format: `type(scope): short description`

Common types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`.

Example: `fix(siem): validate HTTPS URL scheme before sending`

## Pull Request Guidelines

- One logical change per PR.
- Reference any related issues in the PR description.
- PRs require all CI checks to pass before merging.
