# Sudoers Editor UI Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign the Sudoers configuration editor into a modern, split-pane Master-Detail layout with inline command tag management, Active Directory group support, and advanced execution settings (CWD, CHROOT, TIMEOUT).

**Architecture:** Split the editor panel into a left-hand compact rule list and a right-hand rule inspector. Handle AD groups by auto-quoting them in the parsed/serialized config. Extend options parsing to extract/serialize `CWD`, `CHROOT`, and `TIMEOUT` as command-level parameters.

**Tech Stack:** Vanilla JavaScript, CSS, HTML5, Go (for backend validation).

---

### Task 1: Parser & Serializer Redesign (CWD, CHROOT, TIMEOUT, AD Groups)

**Files:**
- Create: `go/cmd/replay-server/static/test_sudoers_parser.js`
- Modify: `go/cmd/replay-server/static/index.html`

- [ ] **Step 1: Write parser/serializer unit tests**
  Create a test script `go/cmd/replay-server/static/test_sudoers_parser.js` that tests the parser and serializer logic using Node.js:
  ```javascript
  const fs = require('fs');
  const path = require('path');

  // Load HTML and extract script content
  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  const scriptContent = html.match(/<script>([\s\S]+?)<\/script>/)[1];

  // Mock DOM variables/functions needed by the script code to evaluate
  const globalMock = {
    esc: (t) => String(t),
    crypto: { subtle: { digest: () => Promise.resolve(new ArrayBuffer(32)) } }
  };

  // Evaluate parser/serializer functions in this context
  const contextFunc = new Function('window', ...Object.keys(globalMock),
    scriptContent + '\nreturn { parseSudoers, serializeSudoers };'
  );
  const { parseSudoers, serializeSudoers } = contextFunc({}, ...Object.values(globalMock));

  // Run test assertions
  function runTests() {
    const rawInput = [
      '# Managed by sudo-logger',
      'User_Alias DEVS = alice, bob',
      '%"Domain Admins" ALL=(ALL:ALL) CWD=/var/www TIMEOUT=120 NOPASSWD: /usr/bin/apt, /bin/systemctl',
      'deployer ALL=(ALL) PASSWD: /usr/bin/git pull',
      ''
    ].join('\n');

    console.log('Testing parseSudoers...');
    const parsed = parseSudoers(rawInput);

    // Validate rules count
    if (parsed.rules.length !== 2) throw new Error(`Expected 2 rules, got ${parsed.rules.length}`);

    // Validate AD Group parsing
    const r1 = parsed.rules[0];
    if (r1.principalType !== 'ad-group') throw new Error(`Expected ad-group, got ${r1.principalType}`);
    if (r1.principalName !== 'Domain Admins') throw new Error(`Expected "Domain Admins", got ${r1.principalName}`);
    if (r1.cwd !== '/var/www') throw new Error(`Expected CWD /var/www, got ${r1.cwd}`);
    if (r1.timeout !== 120) throw new Error(`Expected TIMEOUT 120, got ${r1.timeout}`);
    if (!r1.nopasswd) throw new Error('Expected NOPASSWD true');
    if (r1.cmds.join(',') !== '/usr/bin/apt,/bin/systemctl') throw new Error(`Expected apt,systemctl, got ${r1.cmds}`);

    console.log('Testing serializeSudoers...');
    const serialized = serializeSudoers(parsed.rules, parsed.aliases, parsed.advanced, 'host1', '');
    if (!serialized.includes('%"Domain Admins"')) throw new Error('Serialization missing quoted AD group name');
    if (!serialized.includes('CWD=/var/www')) throw new Error('Serialization missing CWD tag');
    if (!serialized.includes('TIMEOUT=120')) throw new Error('Serialization missing TIMEOUT tag');

    console.log('ALL PARSER TESTS PASSED!');
  }

  runTests();
  ```

- [ ] **Step 2: Run tests to verify failure**
  Run: `node go/cmd/replay-server/static/test_sudoers_parser.js`
  Expected: FAIL (either reference errors or assertion failures because the parsing regex does not support spaces/quotes or CWD/TIMEOUT/CHROOT attributes).

- [ ] **Step 3: Update `parseSudoers` and `serializeSudoers` in `index.html`**
  Modify `/home/alun/sudo-logger/go/cmd/replay-server/static/index.html` to support the new options and quoting.
  Replace `parseSudoers` and `serializeSudoers` with:
  ```javascript
  function parseSudoers(text) {
    const rules = [], aliases = [];
    let advanced = '';
    const advLines = [];
    for (let line of (text || '').split('\n')) {
      const trimmed = line.trim();
      if (trimmed === '' || trimmed.startsWith('#')) continue;

      const aliasMatch = trimmed.match(/^(User_Alias|Cmnd_Alias|Host_Alias|Runas_Alias)\s+(\w+)\s*=\s*(.+)$/);
      if (aliasMatch) {
        aliases.push({ type: aliasMatch[1], name: aliasMatch[2], members: aliasMatch[3].trim() });
        continue;
      }

      if (trimmed.startsWith('Defaults')) { advLines.push(line); continue; }

      const ruleMatch = trimmed.match(/^(%?(?:"[^"]+"|\S+))\s+(\S+)\s*=\s*(?:\(([^)]*)\)\s*)?((?:[A-Z_]+=\S+\s*)*(?:NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|LOG_OUTPUT|NOLOG_INPUT|NOLOG_OUTPUT):\s*)*(.+)$/);
      if (ruleMatch) {
        let principal = ruleMatch[1];
        const hosts = ruleMatch[2];
        const runasRaw = (ruleMatch[3] || 'ALL').trim();
        const [runasUser, runasGroup] = runasRaw.includes(':') ? runasRaw.split(':') : [runasRaw, ''];
        const rest = trimmed.slice(trimmed.indexOf('=') + 1).trim();

        const nopasswd = /\bNOPASSWD\b/.test(rest);
        const noexec   = /\bNOEXEC\b/.test(rest);
        const setenv   = /\bSETENV\b/.test(rest);

        const cwdMatch = rest.match(/\bCWD=(\S+)/);
        const chrootMatch = rest.match(/\bCHROOT=(\S+)/);
        const timeoutMatch = rest.match(/\bTIMEOUT=(\d+)/);

        const cwd = cwdMatch ? cwdMatch[1] : '';
        const chroot = chrootMatch ? chrootMatch[1] : '';
        const timeout = timeoutMatch ? parseInt(timeoutMatch[1], 10) : '';

        const cmdsRaw = rest
          .replace(/\b(CWD|CHROOT|TIMEOUT)=\S+\s*/g, '')
          .replace(/\b(NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|LOG_OUTPUT|NOLOG_INPUT|NOLOG_OUTPUT):\s*/g, '')
          .trim();
        const cmds = cmdsRaw.split(',').map(s => s.trim()).filter(Boolean);

        let principalType = 'user';
        let principalName = principal;
        if (principal.startsWith('%')) {
          principalType = 'group';
          principalName = principal.slice(1);
          if (principalName.startsWith('"') && principalName.endsWith('"')) {
            principalType = 'ad-group';
            principalName = principalName.slice(1, -1);
          }
        }

        rules.push({
          principalType,
          principalName,
          hosts, runasUser: runasUser || 'ALL', runasGroup: runasGroup || '',
          nopasswd, noexec, setenv, cwd, chroot, timeout, cmds,
        });
        continue;
      }
      advLines.push(line);
    }
    advanced = advLines.join('\n');
    return { rules, aliases, advanced };
  }

  function serializeSudoers(rules, aliases, advanced, host, viewer) {
    const now = new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
    const lines = [
      `# Managed by sudo-logger — do not edit manually.`,
      `# Generated: ${now}${viewer ? ' by ' + viewer : ''}`,
      '',
    ];
    for (const a of aliases) {
      if (a.name && a.members) lines.push(`${a.type} ${a.name} = ${a.members}`);
    }
    if (aliases.length) lines.push('');
    for (const r of rules) {
      let principal = '';
      if (r.principalType === 'group') {
        principal = '%' + r.principalName;
      } else if (r.principalType === 'ad-group') {
        principal = r.principalName.includes(' ') ? `%"${r.principalName}"` : `%${r.principalName}`;
      } else {
        principal = r.principalName;
      }

      const runas = r.runasGroup ? `(${r.runasUser}:${r.runasGroup})` : `(${r.runasUser})`;

      const tags = [];
      if (r.cwd) tags.push(`CWD=${r.cwd}`);
      if (r.chroot) tags.push(`CHROOT=${r.chroot}`);
      if (r.timeout) tags.push(`TIMEOUT=${r.timeout}`);
      if (r.nopasswd) tags.push('NOPASSWD:');
      if (r.noexec)   tags.push('NOEXEC:');
      if (r.setenv)   tags.push('SETENV:');

      const cmds = r.cmds.length ? r.cmds.map(c => c.replace(/^\(ALL\)\s+/i, '')).join(', ') : 'ALL';
      const tagStr = tags.length ? tags.join(' ') : '';

      lines.push(`${principal} ${r.hosts || 'ALL'} = ${runas} ${tagStr} ${cmds}`.replace(/\s+/g, ' ').trim());
    }
    if (advanced && advanced.trim()) {
      lines.push('');
      lines.push('# --- advanced ---');
      lines.push(advanced.trim());
    }
    return lines.join('\n') + '\n';
  }
  ```

- [ ] **Step 4: Run tests to verify success**
  Run: `node go/cmd/replay-server/static/test_sudoers_parser.js`
  Expected: PASS

- [ ] **Step 5: Clean up test script and commit**
  Remove the temporary test script:
  `rm go/cmd/replay-server/static/test_sudoers_parser.js`
  Commit the parser/serializer changes:
  ```bash
  git add go/cmd/replay-server/static/index.html
  git commit -m "feat(sudoers): support AD group quoting and advanced parameters (CWD, CHROOT, TIMEOUT)"
  ```

---

### Task 2: Layout & Markup Redesign (HTML & CSS)

**Files:**
- Modify: `go/cmd/replay-server/static/index.html`

- [ ] **Step 1: Replace Sudoers tab markup**
  Replace the contents of `<div class="report-panel" id="tab-sudoers">` (lines ~1713-1723) with a split panel structure:
  ```html
  <div class="report-panel" id="tab-sudoers">
    <div class="sudoers-layout">
      <!-- Host list -->
      <div class="sudoers-host-list" id="sudoers-host-list"></div>

      <!-- Main Split container -->
      <div class="sudoers-main-split">
        <!-- Rule List Column (Left) -->
        <div class="sudoers-rules-column">
          <div class="sudoers-column-header">
            <input type="text" id="sudoers-rule-filter" placeholder="Search rules..." oninput="sudoersSearchQuery=this.value;renderSudoersRulesList()">
            <button class="btn-primary" onclick="addRule()">+ New</button>
          </div>
          <div class="sudoers-rule-list" id="sudoers-rule-list"></div>
        </div>

        <!-- Inspector Panel Column (Right) -->
        <div class="sudoers-inspector-column" id="sudoers-inspector-panel">
          <!-- Populated dynamically via JS -->
        </div>
      </div>
    </div>
  </div>
  ```

- [ ] **Step 2: Add CSS styles**
  Insert the following CSS rules inside the `<style>` block in `static/index.html` (around line ~780):
  ```css
  .sudoers-main-split { display: flex; flex: 1; overflow: hidden; height: 100%; }
  .sudoers-rules-column { width: 280px; flex-shrink: 0; border-right: 1px solid var(--border); display: flex; flex-direction: column; background: #0e1017; }
  .sudoers-column-header { padding: 12px; border-bottom: 1px solid var(--border); display: flex; gap: 8px; }
  .sudoers-column-header input { flex: 1; padding: 6px 10px; font-size: 12px; background: var(--card); border: 1px solid var(--border-mid); color: var(--text); border-radius: 4px; outline: none; }
  .sudoers-rule-list { flex: 1; overflow-y: auto; }

  .sudoers-rule-item { padding: 12px; cursor: pointer; border-bottom: 1px solid rgba(255,255,255,0.03); display: flex; justify-content: space-between; align-items: start; transition: background 0.15s ease; }
  .sudoers-rule-item:hover { background: var(--card-hover); }
  .sudoers-rule-item.active { background: rgba(77, 168, 255, 0.06); border-left: 4px solid var(--blue); }
  .sudoers-rule-item-title { display: flex; align-items: center; gap: 6px; font-weight: 600; font-size: 13px; color: var(--text); }
  .sudoers-rule-item.active .sudoers-rule-item-title { color: var(--blue); }
  .sudoers-rule-item-desc { font-size: 11px; color: var(--text-dim); margin-top: 4px; font-family: monospace; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 170px; }
  .sudoers-rule-item-badges { display: flex; flex-direction: column; align-items: flex-end; gap: 4px; }

  .sudoers-inspector-column { flex: 1; display: flex; flex-direction: column; overflow-y: auto; background: #0c0d14; }
  .sudoers-inspector-header { padding: 12px 20px; border-bottom: 1px solid var(--border); display: flex; justify-content: space-between; align-items: center; }
  .sudoers-inspector-title { font-weight: bold; font-size: 14px; color: var(--text); }
  .sudoers-inspector-subtitle { color: var(--text-dim); font-size: 11px; margin-left: 8px; font-family: monospace; }
  .sudoers-inspector-body { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 20px; }

  .tab-group { display: flex; gap: 4px; background: rgba(0,0,0,0.2); padding: 2px; border-radius: 6px; }
  .tab-item { flex: 1; padding: 6px; font-size: 11px; background: none; border: none; border-radius: 4px; color: var(--text-dim); cursor: pointer; transition: all 0.15s ease; text-align: center; }
  .tab-item.active { background: var(--card); border: 1px solid var(--border-mid); color: var(--blue); font-weight: bold; }
  ```

- [ ] **Step 3: Commit UI Layout & Styles**
  ```bash
  git add go/cmd/replay-server/static/index.html
  git commit -m "feat(sudoers): split layout markup and styling for Master-Detail UI"
  ```

---

### Task 3: JavaScript Visual Editor Implementation

**Files:**
- Modify: `go/cmd/replay-server/static/index.html`

- [ ] **Step 1: Declare state variables**
  Add state variables at the top of the script block (around line ~4760):
  ```javascript
  let sudoersCurrentRuleIdx = -1; // Index of the currently selected rule in sudoersRules
  let sudoersSearchQuery = '';
  ```

- [ ] **Step 2: Rewrite `renderSudoersMain`**
  Modify `renderSudoersMain` to support the split layout columns instead of the previous list:
  ```javascript
  function renderSudoersMain(snaps) {
    const main = document.getElementById('sudoers-main');

    // Clear old container styles to support flex split
    main.style.padding = '0';
    main.style.display = 'flex';
    main.style.height = 'calc(100vh - 130px)';
    main.style.overflow = 'hidden';

    // Populate split container
    const isOverride = sudoersIsOverride || sudoersIsEditing;
    const canEdit = (sudoersCurrentHost === '_default') || isOverride;

    let bannerHtml = '';
    if (sudoersCurrentHost === '_default') {
      bannerHtml = `<div class="sudoers-banner sudoers-banner-main" style="margin:16px;margin-bottom:0">🌐 <strong>Global Template (Main)</strong> - Applies to all default hosts.</div>`;
    } else if (!sudoersIsOverride && !sudoersIsEditing) {
      bannerHtml = `<div class="sudoers-banner sudoers-banner-inherited" style="margin:16px;margin-bottom:0">🔗 <strong>Inheriting Rules</strong>. <button class="btn-sm" onclick="startSudoersCustomizing()" style="margin-left:12px">Create Custom Rules</button></div>`;
    } else if (sudoersIsOverride) {
      bannerHtml = `<div class="sudoers-banner sudoers-banner-custom" style="margin:16px;margin-bottom:0">⚡ <strong>Custom Rules</strong>. <button class="btn-sm btn-danger" onclick="deleteSudoersOverride()" style="margin-left:12px">Discard Custom Rules</button></div>`;
    }

    const host = sudoersCurrentHost;
    const managedSnap = extractManagedSudoers(sudoersCurrentSnap);
    const diffHtml = managedSnap && sudoersCurrentConfig
      ? renderDiff(managedSnap, stripSudoersHeader(sudoersCurrentConfig))
      : '<span class="diff-eq">(no diff available)</span>';

    // Top control elements and columns
    main.innerHTML = `
      <div style="display:flex; flex-direction:column; flex:1; overflow:hidden;">
        ${bannerHtml}

        <div style="display:flex; gap:12px; padding:12px 16px; border-bottom:1px solid var(--border); align-items:center;">
          <div class="sudoers-mode-bar" style="margin-bottom:0">
            <button class="sudoers-mode-btn ${sudoersMode==='visual'?'active':''}" onclick="switchSudoersMode('visual')">Visual Editor</button>
            <button class="sudoers-mode-btn ${sudoersMode==='raw'?'active':''}" onclick="switchSudoersMode('raw')">Technical View (Raw)</button>
          </div>
          <div style="flex:1"></div>
          ${canEdit ? `<button class="btn-primary" onclick="saveSudoersConfig()">Save Configuration</button>` : ''}
        </div>

        <div class="sudoers-main-split" style="opacity: ${canEdit ? '1' : '0.65'}; pointer-events: ${canEdit ? 'auto' : 'none'}">
          <!-- Left Column: Rule list -->
          <div class="sudoers-rules-column">
            <div class="sudoers-column-header">
              <input type="text" id="sudoers-rule-filter" placeholder="Search rules..." value="${esc(sudoersSearchQuery)}" oninput="sudoersSearchQuery=this.value;renderSudoersRulesList()">
              <button class="btn-primary" onclick="addRule()">+ New</button>
            </div>
            <div class="sudoers-rule-list" id="sudoers-rule-list"></div>
          </div>

          <!-- Right Column: Inspector or Raw code editor -->
          <div class="sudoers-inspector-column" id="sudoers-inspector-panel"></div>
        </div>

        <!-- Footers: Diff and history -->
        <div style="border-top:1px solid var(--border); padding:16px; overflow-y:auto; max-height:180px; background:#08090e">
          <div style="font-size:11px; font-weight:bold; color:var(--text-dim); text-transform:uppercase; margin-bottom:8px">Real-time Diff — Host vs Server</div>
          <div class="sudoers-diff" style="margin-bottom:12px">${diffHtml}</div>
          <div style="font-size:11px; font-weight:bold; color:var(--text-dim); text-transform:uppercase; margin-bottom:8px">Snapshot History</div>
          <div class="sudoers-history">
            ${(snaps || []).slice(0, 3).map(s => `
              <div class="sudoers-history-row">
                <span class="sudoers-history-ts">${esc(formatTS(s.uploaded_at))}</span>
                <span class="sudoers-history-sha">${esc(s.sha256.slice(0,16))}…</span>
                <button class="btn-sm" onclick="sudoersViewSnapshot('${esc(s.sha256)}')">View</button>
              </div>
            `).join('') || '<span style="color:var(--text-dim)">No snapshots received yet.</span>'}
          </div>
        </div>
      </div>
    `;

    if (sudoersMode === 'raw') {
      document.getElementById('sudoers-inspector-panel').innerHTML = `
        <div style="padding:20px; display:flex; flex-direction:column; flex:1">
          <div class="sudoers-section-hdr" style="margin-top:0; display:flex; justify-content:space-between; align-items:center">
            <span>Raw sudoers content</span>
            ${sudoersRawEditing
              ? `<button class="btn-sm btn-primary" onclick="const r=document.getElementById('sudoers-raw-area');if(r)sudoersCurrentConfig=r.value;sudoersRawEditing=false;renderSudoersMain(null)">Done editing</button>`
              : `<button class="btn-sm btn-secondary" onclick="sudoersRawEditing=true;renderSudoersMain(null)">Edit</button>`}
          </div>
          ${sudoersRawEditing
            ? `<textarea class="sudoers-raw-area" id="sudoers-raw-area" style="flex:1">${esc(sudoersCurrentConfig)}</textarea>`
            : `<pre class="sudoers-highlighted" style="flex:1; overflow:auto">${highlightSudoers(sudoersCurrentConfig)}</pre>`}
        </div>
      `;
    } else {
      renderSudoersRulesList();
      renderSudoersInspector();
    }
  }
  ```

- [ ] **Step 3: Implement `renderSudoersRulesList`**
  Implement rules rendering inside the list column:
  ```javascript
  function renderSudoersRulesList() {
    const list = document.getElementById('sudoers-rule-list');
    if (!list) return;

    if (!sudoersRules.length) {
      list.innerHTML = `<p style="padding:20px; color:var(--text-dim); text-align:center; font-size:12px">No rules defined.</p>`;
      return;
    }

    const filtered = sudoersRules
      .map((r, i) => ({ r, i }))
      .filter(({ r }) => !sudoersSearchQuery || r.principalName.toLowerCase().includes(sudoersSearchQuery.toLowerCase()));

    list.innerHTML = filtered.map(({ r, i }) => {
      const activeClass = i === sudoersCurrentRuleIdx ? 'active' : '';
      let icon = '👤';
      if (r.principalType === 'group') icon = '👥';
      if (r.principalType === 'ad-group') icon = '🌐';

      const nopasswdBadge = r.nopasswd ? `<span style="font-size:9px; color:var(--green); background:rgba(0,232,122,0.1); padding:1px 4px; border-radius:3px; font-weight:bold;">NOPASSWD</span>` : '';
      const cwdBadge = r.cwd ? `<span style="font-size:9px; color:var(--amber); background:rgba(232,164,77,0.1); padding:1px 4px; border-radius:3px; font-weight:bold;">CWD</span>` : '';

      return `
        <div class="sudoers-rule-item ${activeClass}" onclick="selectSudoersRule(${i})">
          <div>
            <div class="sudoers-rule-item-title">
              <span>${icon}</span>
              <span>${esc(r.principalName || 'unnamed')}</span>
            </div>
            <div class="sudoers-rule-item-desc">${esc(r.cmds.join(', ') || 'ALL')}</div>
          </div>
          <div class="sudoers-rule-item-badges">
            ${nopasswdBadge}
            ${cwdBadge}
          </div>
        </div>
      `;
    }).join('');
  }

  function selectSudoersRule(idx) {
    sudoersCurrentRuleIdx = idx;
    renderSudoersRulesList();
    renderSudoersInspector();
  }
  ```

- [ ] **Step 4: Implement `renderSudoersInspector`**
  Implement the inspector panel generator for active rules:
  ```javascript
  function renderSudoersInspector() {
    const inspector = document.getElementById('sudoers-inspector-panel');
    if (!inspector) return;

    if (sudoersCurrentRuleIdx < 0 || sudoersCurrentRuleIdx >= sudoersRules.length) {
      inspector.innerHTML = `
        <div style="display:flex; align-items:center; justify-content:center; flex:1; color:var(--text-dim); font-size:13px; font-family:var(--font-ui);">
          Select a rule from the list to edit or click "+ New"
        </div>
      `;
      return;
    }

    const r = sudoersRules[sudoersCurrentRuleIdx];
    const adHint = r.principalType === 'ad-group'
      ? `<div style="font-size: 11px; color: var(--text-dim); margin-top: 4px; background: rgba(0, 140, 255, 0.05); border: 1px solid rgba(0, 140, 255, 0.15); padding: 8px 12px; border-radius: 6px; display: flex; align-items: start; gap: 8px; line-height: 1.4;">
          <span style="color: var(--blue);">ℹ️</span>
          <span>Active Directory groups are escaped as <code>%"${esc(r.principalName || '')}"</code> to correctly query SSSD.</span>
         </div>`
      : '';

    const cmdsHtml = r.cmds.map((c, ci) => `
      <div class="sudoers-chip">
        <span>${esc(c)}</span>
        <button class="sudoers-chip-rm" onclick="removeCmd(${sudoersCurrentRuleIdx},${ci})">×</button>
      </div>
    `).join('');

    inspector.innerHTML = `
      <div class="sudoers-inspector-header">
        <div>
          <span class="sudoers-inspector-title">Access Rule Editor</span>
          <span class="sudoers-inspector-subtitle">${esc(r.principalName || '')}</span>
        </div>
        <button style="background:none; border:1px solid rgba(255,80,80,0.4); color:#ff8080; padding:4px 12px; font-size:12px; border-radius:4px; cursor:pointer;" onclick="removeRule(${sudoersCurrentRuleIdx})">Delete Rule</button>
      </div>

      <div class="sudoers-inspector-body">
        <!-- Principal Definition -->
        <div style="display:flex; gap:16px;">
          <div style="flex:1.5;">
            <label style="display:block; font-size:10.5px; color:var(--text-dim); text-transform:uppercase; margin-bottom:6px; font-weight:600;">Principal Type</label>
            <div class="tab-group">
              <button class="tab-item ${r.principalType==='user'?'active':''}" onclick="setPrincipalType('user')">👤 User</button>
              <button class="tab-item ${r.principalType==='group'?'active':''}" onclick="setPrincipalType('group')">👥 Local</button>
              <button class="tab-item ${r.principalType==='ad-group'?'active':''}" onclick="setPrincipalType('ad-group')">🌐 AD Group</button>
            </div>
          </div>
          <div style="flex:2;">
            <label style="display:block; font-size:10.5px; color:var(--text-dim); text-transform:uppercase; margin-bottom:6px; font-weight:600;">Name</label>
            <input type="text" id="inspector-name-input" value="${esc(r.principalName)}" oninput="updateRuleField('principalName', this.value)" style="width:100%; box-sizing:border-box; padding:8px 12px; font-size:13px; background:var(--card); border:1px solid var(--border-mid); color:var(--text); border-radius:6px; outline:none;">
          </div>
        </div>

        ${adHint}

        <!-- Allowed Commands Tag Editor -->
        <div>
          <label style="display:block; font-size:10.5px; color:var(--text-dim); text-transform:uppercase; margin-bottom:6px; font-weight:600;">Allowed Commands</label>
          <div style="border:1px solid var(--border-mid); padding:8px; border-radius:6px; display:flex; flex-wrap:wrap; gap:6px; background:var(--card); min-height:38px; align-items:center;">
            ${cmdsHtml}
            <input type="text" id="inspector-cmd-input" placeholder="+ Type command..." onkeydown="handleCommandKeydown(event, ${sudoersCurrentRuleIdx})" style="border:none; background:none; color:var(--text); font-size:11.5px; font-family:monospace; outline:none; flex:1; min-width:150px;">
          </div>
          <p style="font-size:10.5px; color:var(--text-dim); margin:6px 0 0;">Press <code>Enter</code> or <code>,</code> to add a command tag. Auto-completes paths.</p>
        </div>

        <!-- Security Flags -->
        <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; background:rgba(255,255,255,0.02); padding:12px 16px; border-radius:6px; border:1px solid var(--border);">
          <label style="display:flex; align-items:center; gap:8px; cursor:pointer; font-size:12.5px;">
            <input type="checkbox" ${r.nopasswd?'checked':''} onchange="updateRuleField('nopasswd', this.checked)" style="accent-color:var(--green); transform:scale(1.1);">
            <span>No password</span>
          </label>
          <label style="display:flex; align-items:center; gap:8px; cursor:pointer; font-size:12.5px;">
            <input type="checkbox" ${r.noexec?'checked':''} onchange="updateRuleField('noexec', this.checked)" style="accent-color:var(--amber); transform:scale(1.1);">
            <span>No shell escape</span>
          </label>
          <label style="display:flex; align-items:center; gap:8px; cursor:pointer; font-size:12.5px;">
            <input type="checkbox" ${r.setenv?'checked':''} onchange="updateRuleField('setenv', this.checked)" style="accent-color:var(--blue); transform:scale(1.1);">
            <span>Keep environment</span>
          </label>
        </div>

        <!-- Advanced Limits & Sandboxing -->
        <div>
          <div style="font-size:10.5px; color:var(--text-dim); text-transform:uppercase; margin-bottom:10px; border-bottom:1px solid var(--border); padding-bottom:6px; font-weight:bold;">Advanced Limits & Sandboxing</div>

          <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin-bottom:12px;">
            <div>
              <label style="display:block; font-size:11px; color:var(--text-dim); margin-bottom:4px;">Run As User</label>
              <input type="text" value="${esc(r.runasUser)}" oninput="updateRuleField('runasUser', this.value)" style="width:100%; box-sizing:border-box; padding:6px 10px; font-size:12px; background:var(--card); border:1px solid var(--border-mid); color:var(--text); border-radius:4px; font-family:monospace;">
            </div>
            <div>
              <label style="display:block; font-size:11px; color:var(--text-dim); margin-bottom:4px;">Run As Group</label>
              <input type="text" value="${esc(r.runasGroup)}" oninput="updateRuleField('runasGroup', this.value)" style="width:100%; box-sizing:border-box; padding:6px 10px; font-size:12px; background:var(--card); border:1px solid var(--border-mid); color:var(--text); border-radius:4px; font-family:monospace;">
            </div>
            <div>
              <label style="display:block; font-size:11px; color:var(--text-dim); margin-bottom:4px;">Hosts</label>
              <input type="text" value="${esc(r.hosts)}" oninput="updateRuleField('hosts', this.value)" style="width:100%; box-sizing:border-box; padding:6px 10px; font-size:12px; background:var(--card); border:1px solid var(--border-mid); color:var(--text); border-radius:4px; font-family:monospace;">
            </div>
          </div>

          <div style="display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px;">
            <div>
              <label style="display:block; font-size:11px; color:var(--text-dim); margin-bottom:4px;">Working Dir (CWD)</label>
              <input type="text" value="${esc(r.cwd || '')}" oninput="updateRuleField('cwd', this.value)" style="width:100%; box-sizing:border-box; padding:6px 10px; font-size:12px; background:var(--card); border:1px solid var(--border-mid); color:var(--text); border-radius:4px; font-family:monospace;">
            </div>
            <div>
              <label style="display:block; font-size:11px; color:var(--text-dim); margin-bottom:4px;">Chroot Jail</label>
              <input type="text" value="${esc(r.chroot || '')}" oninput="updateRuleField('chroot', this.value)" style="width:100%; box-sizing:border-box; padding:6px 10px; font-size:12px; background:var(--card); border:1px solid var(--border-mid); color:var(--text); border-radius:4px; font-family:monospace;">
            </div>
            <div>
              <label style="display:block; font-size:11px; color:var(--text-dim); margin-bottom:4px;">Timeout (Seconds)</label>
              <input type="number" value="${esc(r.timeout || '')}" oninput="updateRuleField('timeout', this.value ? parseInt(this.value, 10) : '')" style="width:100%; box-sizing:border-box; padding:6px 10px; font-size:12px; background:var(--card); border:1px solid var(--border-mid); color:var(--text); border-radius:4px; font-family:monospace;">
            </div>
          </div>
        </div>
      </div>
    `;
  }
  ```

- [ ] **Step 5: Implement Mutation & Key Event Helpers**
  Add supporting UI mutation handlers:
  ```javascript
  function updateRuleField(field, val) {
    if (sudoersCurrentRuleIdx >= 0 && sudoersCurrentRuleIdx < sudoersRules.length) {
      sudoersRules[sudoersCurrentRuleIdx][field] = val;

      // Update UI preview & list
      renderSudoersRulesList();

      // Compute raw config updates in memory to sync live diff
      sudoersCurrentConfig = serializeSudoers(sudoersRules, sudoersAliases, sudoersAdvanced, sudoersCurrentHost, '');

      // Re-trigger diff render (only diff block, not full view, to preserve input focus)
      const diffContainer = document.querySelector('.sudoers-diff');
      if (diffContainer) {
        const managedSnap = extractManagedSudoers(sudoersCurrentSnap);
        diffContainer.innerHTML = renderDiff(managedSnap, stripSudoersHeader(sudoersCurrentConfig));
      }
    }
  }

  function setPrincipalType(type) {
    updateRuleField('principalType', type);
    renderSudoersInspector();

    // Focus back on the name field
    const input = document.getElementById('inspector-name-input');
    if (input) input.focus();
  }

  function handleCommandKeydown(event, ruleIdx) {
    if (event.key === 'Enter' || event.key === ',') {
      event.preventDefault();
      const val = event.target.value.trim();
      if (val) {
        sudoersRules[ruleIdx].cmds.push(val);
        event.target.value = '';
        renderSudoersRulesList();
        renderSudoersInspector();

        // Focus back to command tag input
        const cmdInput = document.getElementById('inspector-cmd-input');
        if (cmdInput) cmdInput.focus();
      }
    }
  }

  function addRule() {
    sudoersRules.unshift({
      principalType: 'user',
      principalName: 'new_rule',
      hosts: 'ALL', runasUser: 'ALL', runasGroup: '',
      nopasswd: false, noexec: false, setenv: false,
      cwd: '', chroot: '', timeout: '',
      cmds: ['ALL']
    });
    sudoersIsEditing = true;
    selectSudoersRule(0);
  }

  function removeRule(i) {
    sudoersRules.splice(i, 1);
    sudoersCurrentRuleIdx = sudoersRules.length ? 0 : -1;
    renderSudoersMain(null);
  }

  function removeCmd(ruleIdx, cmdIdx) {
    sudoersRules[ruleIdx].cmds.splice(cmdIdx, 1);
    renderSudoersRulesList();
    renderSudoersInspector();
  }
  ```

- [ ] **Step 6: Commit Visual Editor JS logic**
  ```bash
  git add go/cmd/replay-server/static/index.html
  git commit -m "feat(sudoers): visual editor interaction, inline tagging, and inspector panel"
  ```
