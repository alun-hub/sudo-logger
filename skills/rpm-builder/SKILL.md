---
name: rpm-builder
description: Use when building RPM packages for the sudo-logger project. Guides through versioning, committing changes, and running rpmbuild.
---

# rpm-builder

## Overview
This skill automates the process of building RPM packages for `sudo-logger`. It ensures that all changes are committed (required for `git archive`), versions are synchronized, and the build environment is correctly set up.

## When to Use
- When you need to release a new version of the sudo-logger client, server, or replay web interface.
- When you want to verify that the project builds correctly as an RPM.

## Core Workflow
1. **Verify Version**: Ensure the `Version:` field in `rpm/*.spec` is correct.
2. **Commit Changes**: ALL changes must be committed to git. `git archive` (used for the source tarball) only includes committed files.
3. **Archive**: Create the source tarball in `~/rpmbuild/SOURCES/`.
4. **Build**: Run `rpmbuild` for the desired package.

## Quick Reference

| Package | Spec File | Resulting RPM |
|---------|-----------|---------------|
| Client | `rpm/sudo-logger-client.spec` | `sudo-logger-client-*.rpm` |
| Server | `rpm/sudo-logger-server.spec` | `sudo-logger-server-*.rpm` |
| Replay | `rpm/sudo-logger-replay.spec` | `sudo-logger-replay-*.rpm` |

## Implementation

### Reusable Build Script
This skill includes a script `scripts/build_rpm.sh` that automates the process.

**Usage:**
```bash
./scripts/build_rpm.sh <package-type>
```
Where `<package-type>` is `client`, `server`, or `replay`.

### Manual Build Steps
If you prefer to run steps manually:

```bash
# 1. Set version (must match .spec)
VERSION=1.20.99

# 2. Archive committed HEAD
git archive --format=tar.gz --prefix=sudo-logger-${VERSION}/ HEAD \
    > ~/rpmbuild/SOURCES/sudo-logger-${VERSION}.tar.gz

# 3. Build (e.g., client)
rpmbuild -ba rpm/sudo-logger-client.spec
```

## Common Mistakes
- **Uncommitted Changes**: Changes not committed to git will NOT be included in the RPM because `git archive` only sees the index/HEAD.
- **Version Mismatch**: The `VERSION` env var must exactly match the `Version:` field in the `.spec` file.
- **Missing BuildDeps**: Ensure `rpm-build`, `gcc`, `sudo-devel`, and `golang` are installed.
