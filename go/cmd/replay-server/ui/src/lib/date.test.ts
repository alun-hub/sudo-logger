import { describe, it, expect } from 'vitest'
import { fmtDate, fmtDuration } from './date'

describe('date library', () => {
  it('formats unix timestamps correctly', () => {
    const ts = 1781438400
    expect(fmtDate(ts)).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/)
  })

  it('formats duration correctly', () => {
    expect(fmtDuration(45)).toBe('00:45')
    expect(fmtDuration(3665)).toBe('1:01:05')
  })
})
