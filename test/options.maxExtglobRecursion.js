'use strict';

const assert = require('assert');
const { isMatch, makeRe } = require('..');

describe('options.maxExtglobRecursion', () => {
  it('should literalize risky repeated extglobs by default', () => {
    assert.strictEqual(
      makeRe('+(a|aa)').source,
      '^(?:\\+\\(a\\|aa\\))$'
    );
    assert.strictEqual(
      makeRe('+(*|?)').source,
      '^(?:\\+\\(\\*\\|\\?\\))$'
    );
    assert.strictEqual(
      makeRe('+(+(a))').source,
      '^(?:\\+\\(\\+\\(a\\)\\))$'
    );
    assert.strictEqual(
      makeRe('*(+(a))').source,
      '^(?:\\*\\(\\+\\(a\\)\\))$'
    );

    assert(!isMatch('a'.repeat(20) + 'b', '+(a|aa)'));
    assert(!isMatch('a'.repeat(12) + '!', '+(+(a))'));
  });

  it('should preserve non-risky extglobs by default', () => {
    assert(isMatch('abcabc', '+(abc)'));
    assert(isMatch('foobar', '*(foo|bar)'));
    assert(isMatch('a', '(a|@(b|c)|d)'));
    assert(isMatch('fffooo', '*(*(f)*(o))'));
    assert(isMatch('abc', '+(*)c'));
  });

  it('should allow limited nested repeated extglobs when configured', () => {
    assert.strictEqual(
      makeRe('+(+(a))', { maxExtglobRecursion: 1 }).source,
      '^(?:(?=.)(?:(?:a)+)+)$'
    );
    assert.strictEqual(
      makeRe('*(+(a))', { maxExtglobRecursion: 1 }).source,
      '^(?:(?=.)(?:(?:a)+)*)$'
    );

    assert(isMatch('aaa', '+(+(a))', { maxExtglobRecursion: 1 }));
    assert(isMatch('aaa', '*(+(a))', { maxExtglobRecursion: 1 }));
  });

  it('should still block ambiguous repeated alternation when recursion is allowed', () => {
    assert.strictEqual(
      makeRe('+(a|aa)', { maxExtglobRecursion: 1 }).source,
      '^(?:\\+\\(a\\|aa\\))$'
    );
    assert.strictEqual(
      makeRe('+(*|?)', { maxExtglobRecursion: 1 }).source,
      '^(?:\\+\\(\\*\\|\\?\\))$'
    );
  });

  it('should rewrite risky repeated extglobs embedded in larger patterns', () => {
    assert.strictEqual(
      makeRe('foo/+(a|aa)/bar').source,
      '^(?:foo\\/\\+\\(a\\|aa\\)\\/bar)$'
    );
    assert.strictEqual(
      makeRe('x+(a|aa)y').source,
      '^(?:x\\+\\(a\\|aa\\)y)$'
    );

    assert(isMatch('foo/+(a|aa)/bar', 'foo/+(a|aa)/bar'));
    assert(!isMatch('foo/aa/bar', 'foo/+(a|aa)/bar'));
    assert(isMatch('x+(a|aa)y', 'x+(a|aa)y'));
    assert(!isMatch('xaay', 'x+(a|aa)y'));
  });

  it('should rewrite star-only repeated extglobs embedded in larger patterns', () => {
    assert.strictEqual(
      makeRe('pre*(*(f)*(o))post').source,
      '^(?:pre[fo]*post)$'
    );

    assert(isMatch('prefoopost', 'pre*(*(f)*(o))post'));
  });

  it('should rewrite star-only repeated extglobs', () => {
    assert.strictEqual(
      makeRe('*(*(f))').source,
      '^(?:(?=.)f*)$'
    );

    assert(isMatch('fff', '*(*(f))'));
  });

  it('should rewrite multi-branch star-only repeated extglobs without dropping branches', () => {
    // Regression: the risky-extglob rewrite previously emitted only the first
    // branch, so `+(*(a)|*(b))` collapsed to `a*` and silently stopped matching
    // any string containing `b`. The safe rewrite must preserve every branch.
    assert.strictEqual(
      makeRe('+(*(a)|*(b))').source,
      '^(?:(?=.)[ab]*)$'
    );
    assert.strictEqual(
      makeRe('*(*(a)|c)').source,
      '^(?:(?=.)[ac]*)$'
    );

    for (const str of ['a', 'b', 'ab', 'ba', 'aabb']) {
      assert(isMatch(str, '+(*(a)|*(b))'), `expected to match ${str}`);
    }
    assert(!isMatch('c', '+(*(a)|*(b))'));

    for (const str of ['c', 'a', 'aca', 'cac']) {
      assert(isMatch(str, '*(*(a)|c)'), `expected to match ${str}`);
    }
    assert(!isMatch('d', '*(*(a)|c)'));
  });

  it('should preserve capture behavior for rewritten repeated extglobs', () => {
    const embedded = makeRe('foo/+(a|aa)/bar', { capture: true });
    assert.strictEqual(embedded.source, '^(?:foo\\/\\+\\(a\\|aa\\)\\/bar)$');
    assert.deepStrictEqual(
      Array.from(embedded.exec('foo/+(a|aa)/bar')),
      ['foo/+(a|aa)/bar']
    );

    const simplified = makeRe('*(*(f)*(o))', { capture: true });
    assert.strictEqual(simplified.source, '^(?:(?=.)([fo]*))$');
    assert.deepStrictEqual(
      Array.from(simplified.exec('fffooo')),
      ['fffooo', 'fffooo']
    );
  });

  it('should only rewrite the risky repeated extglob when adjacent extglobs are present', () => {
    assert.strictEqual(
      makeRe('+(a|aa)@(x)').source,
      '^(?:\\+\\(a\\|aa\\)(x))$'
    );

    assert(isMatch('+(a|aa)x', '+(a|aa)@(x)'));
    assert(!isMatch('aaax', '+(a|aa)@(x)'));
  });
  it('should literalize single-branch repeated extglobs with an unanchored star (CVE-2026-112366)', () => {
    // A bare top-level `*` anchored only by a literal to its right keeps an
    // ambiguous left boundary on every repeat iteration, so `+(*a)` compiled to
    // `(?:[^/]*?a)+` and backtracked exponentially. These are now literalized.
    assert.strictEqual(makeRe('+(*a)').source, '^(?:\\+\\(\\*a\\))$');
    assert.strictEqual(makeRe('*(*a)').source, '^(?:\\*\\(\\*a\\))$');
    assert.strictEqual(makeRe('+(*ab)').source, '^(?:\\+\\(\\*ab\\))$');
    assert.strictEqual(makeRe('+(*[ab])').source, '^(?:\\+\\(\\*\\[ab\\]\\))$');
    assert.strictEqual(makeRe('+(**a)').source, '^(?:\\+\\(\\*\\*a\\))$');

    // The multi-branch heuristics only run when there is more than one branch;
    // a single risky branch alongside a safe one must still be caught.
    assert.strictEqual(makeRe('+(*a|b)').source, '^(?:\\+\\(\\*a\\|b\\))$');
    assert.strictEqual(makeRe('+(*a|*b)').source, '^(?:\\+\\(\\*a\\|\\*b\\))$');

    // A leading literal anchors each iteration and stays linear, so it is kept.
    assert.strictEqual(makeRe('+(a*)').source, '^(?:(?=.)(?:a[^/]*?)+)$');
    assert.strictEqual(makeRe('+(x*a)').source, '^(?:(?=.)(?:x[^/]*?a)+)$');
  });

  it('should collapse pure star repeated extglobs to a flat quantifier (CVE-2026-112366)', () => {
    // `+(*)` is redundant repetition of `*`; collapsing it to a single flat
    // quantifier removes the `(?:[^/]*?)+` backtracking while preserving matches.
    assert.strictEqual(makeRe('+(*)').source, '^(?:(?=.)[^/]*)$');
    assert.strictEqual(makeRe('*(*)').source, '^(?:(?=.)[^/]*)$');
    assert.strictEqual(makeRe('+(*)c').source, '^(?:(?=.)[^/]*c)$');

    assert(isMatch('abc', '+(*)c'));
    assert(isMatch('c', '+(*)c'));
    assert(!isMatch('ab/c', '+(*)c'));
    assert(isMatch('abc', '+(*)'));
    assert(!isMatch('', '+(*)'));
  });

  it('should not catastrophically backtrack on repeated extglobs (CVE-2026-112366)', () => {
    const patterns = ['+(*)', '*(*)', '+(*a)', '*(*a)', '+(*ab)', '+(*.js)', '+(*a|*b)'];

    for (const pattern of patterns) {
      const re = makeRe(pattern);
      const start = process.hrtime.bigint();
      // Inputs engineered to force the match to fail: a mostly-uniform run that
      // the vulnerable regexes would partition exponentially before giving up.
      for (const input of ['a'.repeat(50) + '/', 'ab'.repeat(40) + '/', '.js'.repeat(30) + '/']) {
        re.test(input);
      }
      const ms = Number(process.hrtime.bigint() - start) / 1e6;
      assert(ms < 1000, `${pattern} took ${Math.round(ms)}ms (possible ReDoS)`);
    }
  });

  it('should disable the safeguard when maxExtglobRecursion is false', () => {
    assert(
      /\(\?:a\|aa\)\+/.test(
        makeRe('+(a|aa)', { maxExtglobRecursion: false }).source
      )
    );
    assert(
      /\(\?:\(\?:a\)\+\)\+/.test(
        makeRe('+(+(a))', { maxExtglobRecursion: false }).source
      )
    );
  });
});
