// SPDX-License-Identifier: AGPL-3.0-only
/** ADR-007 file-set digests for policy and evaluator build identity. */
import { readdirSync, readFileSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';
import { TextDecoder } from 'node:util';

import type { DomainTag } from './domain.js';
import { digestFor, sha256Hex } from './hash.js';

function filesUnder(root: string, current: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(current, { withFileTypes: true })) {
    const path = resolve(current, entry.name);
    if (entry.isDirectory()) files.push(...filesUnder(root, path));
    else if (entry.isFile()) files.push(path);
    else throw new Error(`unsupported entry in digest file set: ${relative(root, path).split(sep).join('/')}`);
  }
  return files;
}

function normalizedBytes(file: string): Buffer {
  const bytes = readFileSync(file);
  const offset = bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf ? 3 : 0;
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(offset));
  return Buffer.from(text.replace(/\r\n/g, '\n'), 'utf8');
}

/**
 * Hash every file below `root`, with POSIX relative paths and LF-normalized UTF-8
 * bytes. No extension or filename is excluded, so a rule or evaluator input has no
 * unmeasured hiding place.
 */
export function digestFileSet(rootInput: string, domain: Extract<DomainTag, 'policy-set' | 'evaluator-build'>): string {
  const root = resolve(rootInput);
  const entries = filesUnder(root, root)
    .map((file) => ({
      path: relative(root, file).split(sep).join('/'),
      sha256: sha256Hex(normalizedBytes(file)),
    }))
    .sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  return digestFor(domain, entries);
}
