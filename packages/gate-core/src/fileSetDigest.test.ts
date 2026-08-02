// SPDX-License-Identifier: AGPL-3.0-only
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { digestFileSet } from './fileSetDigest.js';

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('ADR-007 file-set digest', () => {
  it('normalizes BOM/CRLF while including every file below the root', () => {
    const left = mkdtempSync(join(tmpdir(), 'file-set-left-'));
    const right = mkdtempSync(join(tmpdir(), 'file-set-right-'));
    roots.push(left, right);
    mkdirSync(join(left, 'nested'));
    mkdirSync(join(right, 'nested'));
    writeFileSync(join(left, 'rule.yaml'), '\ufefffirst\r\nsecond\r\n', 'utf8');
    writeFileSync(join(right, 'rule.yaml'), 'first\nsecond\n', 'utf8');
    writeFileSync(join(left, 'nested', 'extra.any'), 'measured\r\n', 'utf8');
    writeFileSync(join(right, 'nested', 'extra.any'), 'measured\n', 'utf8');

    expect(digestFileSet(left, 'policy-set')).toBe(digestFileSet(right, 'policy-set'));
    writeFileSync(join(right, 'nested', 'unfiltered.bin'), 'also measured', 'utf8');
    expect(digestFileSet(left, 'policy-set')).not.toBe(digestFileSet(right, 'policy-set'));
  });

  it('fails closed on a file that is not valid UTF-8', () => {
    const root = mkdtempSync(join(tmpdir(), 'file-set-invalid-'));
    roots.push(root);
    writeFileSync(join(root, 'invalid.bin'), Buffer.from([0xff]));

    expect(() => digestFileSet(root, 'evaluator-build')).toThrow();
  });
});
