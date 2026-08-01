// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from 'vitest';

import { compareServedId } from './servedModel.js';
import type { ServedIdComparison } from './servedModel.js';

const APERTUS = 'swiss-ai/apertus-v1.5-70b';
const GPT = 'gpt-5.5';

interface Case {
  readonly lane: string;
  readonly requested: unknown;
  readonly policy: unknown;
  readonly served: unknown;
  readonly expect: ServedIdComparison;
  readonly why: string;
}

const cases: readonly Case[] = [
  // publicai — exact-match-required (M0 row 7: served equals requested, no alias indirection)
  {
    lane: 'publicai',
    requested: APERTUS,
    policy: 'exact-match-required',
    served: APERTUS,
    expect: 'exact',
    why: 'served equals requested',
  },
  {
    lane: 'publicai',
    requested: APERTUS,
    policy: 'exact-match-required',
    served: `${APERTUS}-2026-04-23`,
    expect: 'mismatch',
    why: 'an exact-match lane does not accept a dated snapshot',
  },
  {
    lane: 'publicai',
    requested: APERTUS,
    policy: 'exact-match-required',
    served: 'swiss-ai/apertus-v1.5-8b',
    expect: 'mismatch',
    why: 'a different model behind the endpoint',
  },

  // openai — alias-to-dated-snapshot (M0 row 8: gpt-5.5 -> gpt-5.5-2026-04-23)
  {
    lane: 'openai',
    requested: GPT,
    policy: 'alias-to-dated-snapshot',
    served: GPT,
    expect: 'exact',
    why: 'the alias itself came back',
  },
  {
    lane: 'openai',
    requested: GPT,
    policy: 'alias-to-dated-snapshot',
    served: 'gpt-5.5-2026-04-23',
    expect: 'benign-resolution',
    why: 'the observed alias resolution',
  },
  {
    lane: 'openai',
    requested: GPT,
    policy: 'alias-to-dated-snapshot',
    served: 'gpt-5.5-2026-4-23',
    expect: 'mismatch',
    why: 'the date shape must be \\d{4}-\\d{2}-\\d{2}',
  },
  {
    lane: 'openai',
    requested: GPT,
    policy: 'alias-to-dated-snapshot',
    served: 'gpt-5x5-2026-04-23',
    expect: 'mismatch',
    why: 'the dot in the alias is a literal, not a wildcard',
  },
  {
    lane: 'openai',
    requested: GPT,
    policy: 'alias-to-dated-snapshot',
    served: 'gpt-55-2026-04-23',
    expect: 'mismatch',
    why: 'the dot is not optional either',
  },
  {
    lane: 'openai',
    requested: GPT,
    policy: 'alias-to-dated-snapshot',
    served: 'gpt-5.5-2026-04-23-preview',
    expect: 'mismatch',
    why: 'the pattern is anchored at both ends',
  },
  {
    lane: 'openai',
    requested: GPT,
    policy: 'alias-to-dated-snapshot',
    served: 'gpt-5.6-2026-04-23',
    expect: 'mismatch',
    why: 'a different model, dated',
  },
  {
    lane: 'openai',
    requested: GPT,
    policy: 'alias-to-dated-snapshot',
    served: 'GPT-5.5',
    expect: 'mismatch',
    why: 'ids are compared exactly; no case folding',
  },

  // Missing or malformed served ids -> mismatch -> beat-21 quarantine, fail closed.
  { lane: 'openai', requested: GPT, policy: 'alias-to-dated-snapshot', served: undefined, expect: 'mismatch', why: 'absent served id' },
  { lane: 'openai', requested: GPT, policy: 'alias-to-dated-snapshot', served: null, expect: 'mismatch', why: 'null served id' },
  { lane: 'openai', requested: GPT, policy: 'alias-to-dated-snapshot', served: '', expect: 'mismatch', why: 'empty served id' },
  { lane: 'openai', requested: GPT, policy: 'alias-to-dated-snapshot', served: '   ', expect: 'mismatch', why: 'whitespace served id' },
  { lane: 'openai', requested: GPT, policy: 'alias-to-dated-snapshot', served: ` ${GPT}`, expect: 'mismatch', why: 'no silent trimming' },
  { lane: 'openai', requested: GPT, policy: 'alias-to-dated-snapshot', served: `${GPT}\n`, expect: 'mismatch', why: 'a trailing newline is malformed' },
  { lane: 'openai', requested: GPT, policy: 'alias-to-dated-snapshot', served: 123, expect: 'mismatch', why: 'a non-string served id' },
  { lane: 'openai', requested: GPT, policy: 'alias-to-dated-snapshot', served: { id: GPT }, expect: 'mismatch', why: 'an object served id' },

  // Malformed inputs on the other two arguments fail closed the same way.
  { lane: 'openai', requested: GPT, policy: 'alias-to-anything', served: GPT, expect: 'mismatch', why: 'an unknown resolution policy' },
  { lane: 'openai', requested: GPT, policy: undefined, served: GPT, expect: 'mismatch', why: 'an absent policy' },
  { lane: 'openai', requested: '', policy: 'alias-to-dated-snapshot', served: GPT, expect: 'mismatch', why: 'an empty requested id' },
  { lane: 'openai', requested: undefined, policy: 'alias-to-dated-snapshot', served: GPT, expect: 'mismatch', why: 'an absent requested id' },
];

describe('compareServedId — ADR-006 §3', () => {
  it.each(cases.map((c) => [`${c.lane}: ${c.why}`, c] as const))('%s', (_name, testCase) => {
    expect(compareServedId(testCase.requested, testCase.policy, testCase.served)).toBe(testCase.expect);
  });

  it('is a pure function of the three arguments', () => {
    const first = compareServedId(GPT, 'alias-to-dated-snapshot', 'gpt-5.5-2026-04-23');
    const second = compareServedId(GPT, 'alias-to-dated-snapshot', 'gpt-5.5-2026-04-23');
    expect(first).toBe(second);
    expect(first).toBe('benign-resolution');
  });

  it('covers all three outcomes', () => {
    expect(new Set(cases.map((c) => c.expect))).toEqual(new Set(['exact', 'benign-resolution', 'mismatch']));
  });
});
