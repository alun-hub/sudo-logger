import { describe, it, expect } from 'vitest'
import { parseSudoers, serializeSudoers } from './sudoers'

describe('sudoers parser', () => {
  it('parses basic user rules', () => {
    const text = 'alice ALL=(ALL) ALL'
    const { rules } = parseSudoers(text)
    expect(rules).toHaveLength(1)
    expect(rules[0]).toMatchObject({
      principalType: 'user',
      principalName: 'alice',
      hosts: 'ALL',
      runasUser: 'ALL',
      cmds: ['ALL']
    })
  })

  it('parses group rules', () => {
    const text = '%admins ALL=(root) NOPASSWD: /usr/bin/apt'
    const { rules } = parseSudoers(text)
    expect(rules).toHaveLength(1)
    expect(rules[0]).toMatchObject({
      principalType: 'group',
      principalName: 'admins',
      nopasswd: true,
      cmds: ['/usr/bin/apt']
    })
  })

  it('parses AD group rules with spaces', () => {
    const text = '%"Domain Admins" ALL=(ALL) ALL'
    const { rules } = parseSudoers(text)
    expect(rules).toHaveLength(1)
    expect(rules[0]).toMatchObject({
      principalType: 'ad-group',
      principalName: 'Domain Admins'
    })
  })

  it('parses rules with multiple commands and tags', () => {
    const text = 'bob ALL=(ALL) NOEXEC: SETENV: /usr/bin/vi, /usr/bin/view'
    const { rules } = parseSudoers(text)
    expect(rules[0].noexec).toBe(true)
    expect(rules[0].setenv).toBe(true)
    expect(rules[0].cmds).toEqual(['/usr/bin/vi', '/usr/bin/view'])
  })

  it('parses modern tags like CWD and TIMEOUT', () => {
    const text = 'deploy ALL=(ALL) CWD=/var/www TIMEOUT=30 /usr/bin/git'
    const { rules } = parseSudoers(text)
    expect(rules[0].cwd).toBe('/var/www')
    expect(rules[0].timeout).toBe(30)
  })

  it('handles aliases', () => {
    const text = 'User_Alias ADMINS = alice, bob\nADMINS ALL=(ALL) ALL'
    const { rules, aliases } = parseSudoers(text)
    expect(aliases).toHaveLength(1)
    expect(aliases[0]).toEqual({ type: 'User_Alias', name: 'ADMINS', members: 'alice, bob' })
    expect(rules[0].principalName).toBe('ADMINS')
  })
})

describe('sudoers serializer', () => {
  it('roundtrips a complex file', () => {
    const input = 'alice ALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/dpkg\n'
    const parsed = parseSudoers(input)
    const output = serializeSudoers(parsed.rules, parsed.aliases, parsed.advanced)

    // Serializer adds headers, so we check if the rule line is present
    expect(output).toContain('alice ALL = (ALL) NOPASSWD: /usr/bin/apt, /usr/bin/dpkg')
  })

  it('serializes AD groups correctly', () => {
    const rule = {
      principalType: 'ad-group' as const,
      principalName: 'Domain Admins',
      hosts: 'ALL',
      runasUser: 'ALL',
      runasGroup: '',
      nopasswd: false,
      noexec: false,
      setenv: false,
      cmds: ['ALL']
    }
    const output = serializeSudoers([rule], [], '')
    expect(output).toContain('%Domain\\ Admins ALL = (ALL) ALL')
  })
})
