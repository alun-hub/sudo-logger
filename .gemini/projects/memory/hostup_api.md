# HostUp API Memory Reference

## Overview
This document records how to access and use the HostUp API within the `sudo-logger` project context for testing, scripting, or integration.

## Configuration
- **Base URL:** `https://cloud.hostup.se`
- **Interactive Documentation:** `https://developer.hostup.se/`
- **Grouped Endpoints Index:** `https://developer.hostup.se/llms.txt`
- **Complete API Specification:** `https://developer.hostup.se/llms-full.txt` (contains schemas, curl examples, and payloads).

## Authentication
- Access is authenticated via an API key.
- The key is saved in the user's `~/.bashrc` file under the environment variable `HOSTUP_API_KEY`.
- Because AI assistant commands run in non-interactive shell sessions, the key is not loaded by default.

### Usage in Shell Commands
To execute API requests, you must prefix commands with `source ~/.bashrc` to export the environment variable:
```bash
source ~/.bashrc && curl -s -X GET "https://cloud.hostup.se/api/v2/me" \
  -H "Authorization: Bearer $HOSTUP_API_KEY" \
  -H "Accept: application/json"
```

## Scopes & Account Information
- The configured token belongs to account **Andreas Lundqvist** (`alun@alun.se`).
- The token possesses full capabilities, including `read:all`, `write:all`, `read:vm`, `write:vm`, `read:domains`, `write:domains`, etc.
