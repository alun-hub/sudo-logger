export interface SudoersRule {
  principalType: 'user' | 'group' | 'ad-group'
  principalName: string
  hosts: string
  runasUser: string
  runasGroup: string
  nopasswd: boolean
  noexec: boolean
  setenv: boolean
  cwd?: string
  chroot?: string
  timeout?: number | string
  cmds: string[]
}

export interface SudoersAlias {
  type: string
  name: string
  members: string
}

export interface ParsedSudoers {
  rules: SudoersRule[]
  aliases: SudoersAlias[]
  advanced: string
}

export function parseSudoers(text: string): ParsedSudoers {
  const rules: SudoersRule[] = []
  const aliases: SudoersAlias[] = []
  const advLines: string[] = []

  for (const line of (text || '').split('\n')) {
    const trimmed = line.trim()
    if (trimmed === '' || trimmed.startsWith('#')) continue

    const aliasMatch = trimmed.match(/^(User_Alias|Cmnd_Alias|Host_Alias|Runas_Alias)\s+(\w+)\s*=\s*(.+)$/)
    if (aliasMatch) {
      aliases.push({ type: aliasMatch[1], name: aliasMatch[2], members: aliasMatch[3].trim() })
      continue
    }

    if (trimmed.startsWith('Defaults')) { advLines.push(line); continue }

    const eqIndex = trimmed.indexOf('=')
    if (eqIndex !== -1) {
      const left = trimmed.slice(0, eqIndex).trim()
      const right = trimmed.slice(eqIndex + 1).trim()

      const principalMatch = left.match(/^(%?"[^"]+"|\S+(?:\\ \S+)*)\s+(.+)$/)
      if (principalMatch) {
        const principal = principalMatch[1]
        const hosts = principalMatch[2]

        let principalType: 'user' | 'group' | 'ad-group' = 'user'
        let principalName = principal

        if (principal.startsWith('%"')) {
          principalType = 'ad-group'
          principalName = principal.slice(2, -1)
        } else if (principal.startsWith('"')) {
          principalType = 'user'
          principalName = principal.slice(1, -1)
        } else if (principal.startsWith('%')) {
          const rawName = principal.slice(1).replace(/\\ /g, ' ')
          principalType = rawName.includes(' ') ? 'ad-group' : 'group'
          principalName = rawName
        }

        let runasRaw = 'ALL'
        let restAfterRunas = right
        const runasMatch = right.match(/^\(([^)]+)\)\s*(.*)$/)
        if (runasMatch) {
          runasRaw = runasMatch[1].trim()
          restAfterRunas = runasMatch[2].trim()
        }
        const runasparts = runasRaw.includes(':') ? runasRaw.split(':') : [runasRaw, '']
        const runasUser = runasparts[0]
        const runasGroup = runasparts[1] ?? ''

        let temp = restAfterRunas
        let cwd: string | undefined
        let chroot: string | undefined
        let timeout: number | undefined
        let nopasswd = false
        let noexec = false
        let setenv = false

        while (true) {
          temp = temp.trim()
          const tagMatch = temp.match(/^(NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|LOG_OUTPUT|NOLOG_INPUT|NOLOG_OUTPUT):\s*/i)
          if (tagMatch) {
            const tag = tagMatch[1].toUpperCase()
            if (tag === 'NOPASSWD') nopasswd = true
            if (tag === 'PASSWD')   nopasswd = false
            if (tag === 'NOEXEC')   noexec = true
            if (tag === 'EXEC')     noexec = false
            if (tag === 'SETENV')   setenv = true
            if (tag === 'NOSETENV') setenv = false
            temp = temp.slice(tagMatch[0].length)
            continue
          }
          const cwdMatch = temp.match(/^CWD=(?:"([^"]+)"|(\S+))\s*/i)
          if (cwdMatch) { cwd = cwdMatch[1] || cwdMatch[2]; temp = temp.slice(cwdMatch[0].length); continue }
          const chrootMatch = temp.match(/^CHROOT=(?:"([^"]+)"|(\S+))\s*/i)
          if (chrootMatch) { chroot = chrootMatch[1] || chrootMatch[2]; temp = temp.slice(chrootMatch[0].length); continue }
          const timeoutMatch = temp.match(/^TIMEOUT=(\d+)\s*/i)
          if (timeoutMatch) { timeout = parseInt(timeoutMatch[1], 10); temp = temp.slice(timeoutMatch[0].length); continue }
          break
        }

        const cmds = temp.split(',').map(s => s.trim()).filter(Boolean)
        rules.push({ principalType, principalName, hosts, runasUser: runasUser || 'ALL', runasGroup: runasGroup || '', nopasswd, noexec, setenv, cwd, chroot, timeout, cmds })
        continue
      }
    }
    advLines.push(line)
  }

  return { rules, aliases, advanced: advLines.join('\n') }
}

export function serializeSudoers(rules: SudoersRule[], aliases: SudoersAlias[], advanced: string): string {
  const now = new Date().toISOString().slice(0, 16).replace('T', ' ') + ' UTC'
  const lines: string[] = [
    `# Managed by sudo-logger — do not edit manually.`,
    `# Generated: ${now}`,
    '',
  ]
  for (const a of aliases) {
    // Collapse embedded newlines (same treatment as rule lines below) so a
    // pasted multi-line alias name/member list can't inject an extra
    // sudoers directive line.
    if (a.name && a.members) lines.push(`${a.type} ${a.name} = ${a.members}`.replace(/\s+/g, ' ').trim())
  }
  if (aliases.length) lines.push('')

  for (const r of rules) {
    let principal = r.principalName
    if (r.principalType === 'ad-group') {
      principal = '%' + r.principalName.replace(/ /g, '\\ ')
    } else if (r.principalType === 'group') {
      principal = r.principalName.includes(' ')
        ? '%' + r.principalName.replace(/ /g, '\\ ')
        : `%${r.principalName}`
    } else if (r.principalType === 'user' && r.principalName.includes(' ')) {
      principal = `"${r.principalName}"`
    }

    const runas = r.runasGroup ? `(${r.runasUser}:${r.runasGroup})` : `(${r.runasUser})`
    const opts: string[] = []
    if (r.cwd)     opts.push(`CWD=${r.cwd.includes(' ') ? `"${r.cwd}"` : r.cwd}`)
    if (r.chroot)  opts.push(`CHROOT=${r.chroot.includes(' ') ? `"${r.chroot}"` : r.chroot}`)
    if (r.timeout) opts.push(`TIMEOUT=${r.timeout}`)
    if (r.nopasswd) opts.push('NOPASSWD:')
    if (r.noexec)   opts.push('NOEXEC:')
    if (r.setenv)   opts.push('SETENV:')

    const cmds = r.cmds.length ? r.cmds.join(', ') : 'ALL'
    const optStr = opts.length ? opts.join(' ') + ' ' : ''
    lines.push(`${principal} ${r.hosts || 'ALL'} = ${runas} ${optStr}${cmds}`.replace(/\s+/g, ' ').trim())
  }

  if (advanced && advanced.trim()) {
    lines.push('')
    lines.push('# --- advanced ---')
    lines.push(advanced.trim())
  }
  return lines.join('\n') + '\n'
}
