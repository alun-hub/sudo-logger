# Design Spec: Sudoers Tab UI Redesign & Advanced Settings
**Date:** 2026-06-05 22:25
**Status:** Draft / Approved by User

---

## 1. Overview & Goals
The existing Sudoers management tab in the `replay-server` Web UI is functional but lacks modern usability standards and does not support advanced sudoers parameters required by high-security environments.

The goals of this redesign are:
* **Simplify Layout:** Replace the long vertical list of bulky cards with a two-pane **Master-Detail Split Panel** layout.
* **Modernize Interactions:** Eliminate native browser `prompt()` dialogs, replacing them with inline creation inputs and tags.
* **Expand Capabilities:** Integrate support for Active Directory/LDAP groups, execution timeouts, custom working directories, and chroot environments.
* **Enhance Safety:** Provide a real-time syntax preview showing exactly what code will be written to `/etc/sudoers.d/` on deployment.

---

## 2. UI/UX Specifications

### 2.1 The Two-Pane Split Layout
We will split the `.sudoers-main` container into a flexbox layout (`.sudoers-layout` inside the main editor tab):
1. **Rule List (Left Panel - 280px width):**
   * A search filter input box at the top to isolate rules by user or command.
   * A `+ New` button that prepends a blank rule to the list and selects it (no popup dialogs).
   * Compact rule list items showing:
     * Principal type icon: 👤 User, 👥 Local Group, or 🌐 AD Group.
     * Principal name.
     * Snippet of allowed commands.
     * Quick indicator badges for active modifiers (e.g. `NOPASSWD` in green, `CWD` in amber).
2. **Rule Inspector (Right Panel - Flex-grow):**
   * Dedicated edit pane that displays when a rule is selected.
   * **Principal Type Tabs:** A toggle selector between `User`, `Local Group`, and `AD Group`.
   * **Inline Tag Editor for Commands:** An input field where typing a path and pressing `Enter` or `,` appends it to the list as a tag chip.
   * **Flags Grid:** Multi-column checkbox grid for `NOPASSWD`, `NOEXEC`, and `SETENV`.
   * **Advanced Grid:** Text inputs for `CWD` (Working Directory), `CHROOT` (Chroot Jail), `TIMEOUT` (execution timeout in seconds), and `RunasUser`/`RunasGroup`/`Hosts`.

### 2.2 Active Directory (AD) Group Handling
* In standard `sudoers`, AD groups queried via SSSD/NSS are referenced as `%groupname`.
* If the name contains spaces, it must be double-quoted (e.g. `%"Domain Admins"`).
* Selecting the **AD Group** type in the UI will automatically guide the administrator, showing an inline info banner, and handle necessary quoting and escaping under the hood during serialization.

---

## 3. Technical Implementation & Data Model

### 3.1 JavaScript Data Structure
The `sudoersRules` array elements will be updated to include new fields:
```javascript
{
  principalType: 'user' | 'group' | 'ad-group',
  principalName: string,
  hosts: string,
  runasUser: string,
  runasGroup: string,
  nopasswd: boolean,
  noexec: boolean,
  setenv: boolean,
  cwd: string,        // New: target working directory (CWD=...)
  chroot: string,     // New: chroot path (CHROOT=...)
  timeout: number,    // New: execution timeout limit (TIMEOUT=...)
  cmds: string[]
}
```

### 3.2 Parser (`parseSudoers`) Redesign
The parser function in `go/cmd/replay-server/static/index.html#L4617` must be updated:
1. **Principal RegEx:** Fix the regular expression to allow quoted principals with spaces.
   * *Current regex:* `/^(%?\S+)/`
   * *New regex:* `/^(%?(?:"[^"]+"|\S+))/`
2. **Parameter Extraction:** When parsing a rule's options, match and extract `CWD=`, `CHROOT=`, and `TIMEOUT=` values:
   ```javascript
   // Regex to find CWD, CHROOT, and TIMEOUT
   const cwdMatch = rest.match(/\bCWD=(\S+)/);
   const chrootMatch = rest.match(/\bCHROOT=(\S+)/);
   const timeoutMatch = rest.match(/\bTIMEOUT=(\d+)/);
   ```
3. **AD Group Detection:** If the parsed principal name starts with `%"` and ends with `"`, set `principalType = 'ad-group'` and strip the outer quotes for display in the input box.

### 3.3 Serializer (`serializeSudoers`) Redesign
The serializer in `go/cmd/replay-server/static/index.html#L4661` will be updated to format the new options:
* **AD Group Quoting:**
  ```javascript
  let principal = '';
  if (r.principalType === 'group') {
    principal = '%' + r.principalName;
  } else if (r.principalType === 'ad-group') {
    // Quote if contains spaces or special characters
    principal = r.principalName.includes(' ') ? `%"${r.principalName}"` : `%${r.principalName}`;
  } else {
    principal = r.principalName;
  }
  ```
* **Advanced Tags Insertion:**
  ```javascript
  const tags = [];
  if (r.cwd) tags.push(`CWD=${r.cwd}`);
  if (r.chroot) tags.push(`CHROOT=${r.chroot}`);
  if (r.timeout) tags.push(`TIMEOUT=${r.timeout}`);
  if (r.nopasswd) tags.push('NOPASSWD:');
  if (r.noexec) tags.push('NOEXEC:');
  if (r.setenv) tags.push('SETENV:');
  ```
  These tags are joined and placed immediately before the command list.

---

## 4. Testing & Verification Plan

### 4.1 Unit Testing Sudoers Serialization
We will implement client-side unit tests (or validation checkpoints in `static/index.html` handlers) verifying:
* A rule with `CWD` and `TIMEOUT` correctly serializes to:
  `%"Domain Admins" ALL=(ALL:ALL) CWD=/var/www TIMEOUT=120 NOPASSWD: /usr/bin/apt`
* That same serialized string parses back into identical JavaScript objects (round-trip validation).

### 4.2 Live Syntax Validation
When editing in the Visual Editor, the live output preview is dynamically updated. We will implement simple checks:
* Verify that timeouts are positive integers.
* Ensure paths are absolute (starting with `/`).
* Highlight any invalid characters or formatting errors prior to hitting "Save".
