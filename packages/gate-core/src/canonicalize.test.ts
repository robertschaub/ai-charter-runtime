// SPDX-License-Identifier: AGPL-3.0-only
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { CanonicalizationError, canonicalize } from './canonicalize.js';
import type { CanonicalizationErrorCode } from './canonicalize.js';

interface Vector {
  name: string;
  source: string;
  note?: string;
  input: unknown;
  expected: string;
}

interface Rejection {
  case: string;
  code: CanonicalizationErrorCode;
  why: string;
}

function loadFixture<T>(relative: string): T {
  const path = fileURLToPath(new URL(`../../../fixtures/jcs/${relative}`, import.meta.url));
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}

const vectors = loadFixture<Vector[]>('vectors.json');
const rejections = loadFixture<Rejection[]>('rejections.json');

/**
 * Every rejection class of ADR-007, constructed in code because JSON cannot express NaN,
 * BigInt, Date, Map, Set, undefined, functions, symbols, or a cycle.
 */
const rejectionCases: Record<string, () => unknown> = {
  'non-integer-number': () => ({ amount: 1.5 }),
  nan: () => ({ n: Number.NaN }),
  infinity: () => ({ n: Number.POSITIVE_INFINITY }),
  'negative-infinity': () => ({ n: Number.NEGATIVE_INFINITY }),
  'unsafe-integer': () => ({ n: Number.MAX_SAFE_INTEGER + 2 }),
  'unsafe-integer-negative': () => ({ n: -(Number.MAX_SAFE_INTEGER + 2) }),
  'exponent-integer': () => ({ n: 1e21 }),
  bigint: () => ({ n: 1n }),
  'undefined-root': () => undefined,
  'undefined-in-array': () => [1, undefined, 3],
  'undefined-property': () => ({ a: undefined }),
  date: () => ({ at: new Date('2026-08-01T09:32:14.512Z') }),
  map: () => ({ m: new Map([['a', 1]]) }),
  set: () => ({ s: new Set([1]) }),
  'class-instance': () => {
    class Holder {
      value = 1;
    }
    return { h: new Holder() };
  },
  'array-subclass': () => {
    class Tags extends Array<string> {}
    const tags = new Tags();
    tags.push('conf:case');
    return { tags };
  },
  'lone-high-surrogate-value': () => ({ s: '\ud800' }),
  'lone-low-surrogate-value': () => ({ s: 'a\udfffb' }),
  'lone-surrogate-key': () => ({ ['\ud800']: 1 }),
  function: () => ({ f: () => 1 }),
  symbol: () => ({ s: Symbol('x') }),
  cycle: () => {
    const root: Record<string, unknown> = { a: 1 };
    root['self'] = root;
    return root;
  },
};

describe('canonicalize — committed vectors', () => {
  it.each(vectors.map((vector) => [vector.name, vector] as const))('%s', (_name, vector) => {
    expect(canonicalize(vector.input)).toBe(vector.expected);
  });

  // The other direction: re-parsing the canonical form must reproduce it byte for byte.
  it.each(vectors.map((vector) => [vector.name, vector] as const))(
    '%s round-trips through JSON.parse',
    (_name, vector) => {
      expect(canonicalize(JSON.parse(vector.expected))).toBe(vector.expected);
    },
  );

  it('covers the RFC 8785 surrogate-ordering property', () => {
    const vector = vectors.find((candidate) => candidate.name === 'rfc8785-key-ordering');
    expect(vector).toBeDefined();
    // U+D83D (the smiley's high surrogate) sorts before U+FB33, which is the whole point.
    const smileyIndex = (vector as Vector).expected.indexOf('😂');
    const daletIndex = (vector as Vector).expected.indexOf('דּ');
    expect(smileyIndex).toBeGreaterThan(-1);
    expect(daletIndex).toBeGreaterThan(smileyIndex);
  });
});

describe('canonicalize — the subset is enforced by throwing', () => {
  it.each(rejections.map((rejection) => [rejection.case, rejection] as const))(
    'rejects %s',
    (_name, rejection) => {
      const build = rejectionCases[rejection.case];
      expect(build, `no constructed value for fixture case ${rejection.case}`).toBeDefined();
      let thrown: unknown;
      try {
        canonicalize((build as () => unknown)());
      } catch (error) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(CanonicalizationError);
      expect((thrown as CanonicalizationError).code).toBe(rejection.code);
    },
  );

  // Both directions: no constructed case may drift out of the committed list.
  it('lists every constructed rejection case in the fixture', () => {
    expect(Object.keys(rejectionCases).sort()).toEqual(rejections.map((r) => r.case).sort());
  });

  it('reports the path of the offending value', () => {
    try {
      canonicalize({ limits: { amount_minor_units: 25.5 } });
      expect.unreachable('should have thrown');
    } catch (error) {
      expect((error as CanonicalizationError).path).toBe('/limits/amount_minor_units');
    }
  });

  it('accepts a null-prototype object as a plain object', () => {
    const value = Object.create(null) as Record<string, unknown>;
    value['a'] = 1;
    expect(canonicalize(value)).toBe('{"a":1}');
  });
});
