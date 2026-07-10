# Security Policy

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security vulnerabilities by using [GitHub's private vulnerability
reporting](https://github.com/alun-hub/sudo-logger/security/advisories/new)
or by emailing the maintainer directly (see the GitHub profile). Include a
description of the issue, steps to reproduce, and potential impact.

## Supported Versions

Only the latest tagged release is supported. Fixes land on `main` and ship
in the next release; there are no backported patch releases for older
versions.

## Scope

sudo-logger streams sudo session I/O to a central log server and enforces
logging via Linux cgroups, so vulnerabilities of particular interest
include:

- Bypasses of the mandatory-logging/freeze mechanism
- TLS, authentication, or RBAC bypasses in the agent, server, or
  replay-server
- Anything that lets a monitored session evade or corrupt its audit trail
