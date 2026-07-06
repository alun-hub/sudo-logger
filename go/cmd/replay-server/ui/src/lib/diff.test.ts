import { describe, it, expect } from 'vitest'
import { summarizeLineDiff } from './diff'

describe('summarizeLineDiff', () => {
  it('reports no change when content is identical', () => {
    expect(summarizeLineDiff('a\nb\n', 'a\nb\n')).toEqual({ added: [], removed: [] })
  })

  it('reports a pure addition', () => {
    expect(summarizeLineDiff('a\n', 'a\nb\n')).toEqual({ added: ['b'], removed: [] })
  })

  it('reports a pure removal', () => {
    expect(summarizeLineDiff('a\nb\n', 'a\n')).toEqual({ added: [], removed: ['b'] })
  })

  it('reports a replaced line as one add and one remove', () => {
    const { added, removed } = summarizeLineDiff('a\nb\nc\n', 'a\nx\nc\n')
    expect(added).toEqual(['x'])
    expect(removed).toEqual(['b'])
  })

  it('does not count a trailing newline as a phantom empty line', () => {
    expect(summarizeLineDiff('a\nb\n', 'a\nb')).toEqual({ added: [], removed: [] })
  })

  it('handles empty old content', () => {
    const { added, removed } = summarizeLineDiff('', 'a\nb\n')
    expect(added.sort()).toEqual(['a', 'b'])
    expect(removed).toEqual([])
  })

  it('handles empty new content', () => {
    const { added, removed } = summarizeLineDiff('a\nb\n', '')
    expect(added).toEqual([])
    expect(removed.sort()).toEqual(['a', 'b'])
  })

  it('handles both empty', () => {
    expect(summarizeLineDiff('', '')).toEqual({ added: [], removed: [] })
  })
})
