// SPDX-License-Identifier: AGPL-3.0-only
import { mkdtempSync, readFileSync, rmSync, statSync, truncateSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { canonicalize } from './canonicalize.js';
import { ChainError, GENESIS_PREV_HASH, appendEntry, readHead, verifyChain } from './chain.js';
import { digestFor } from './hash.js';

let dir: string;
let file: string;

beforeEach(() => {
  // Never under records/: those files are part of the system under test (AGENTS.md).
  dir = mkdtempSync(join(tmpdir(), 'gate-core-chain-'));
  file = join(dir, 'action.jsonl');
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function seed(count: number): string[] {
  const hashes: string[] = [];
  for (let index = 0; index < count; index += 1) {
    const appended = appendEntry(file, 'record-entry', {
      world_id: 'w-demo',
      entry_id: `rec_${index}`,
      payload: { event: 'commitment' },
    });
    hashes.push(appended.entry_hash);
  }
  return hashes;
}

function lines(): string[] {
  return readFileSync(file, 'utf8').split('\n').slice(0, -1);
}

function rewriteLine(index: number, mutate: (entry: Record<string, unknown>) => void): void {
  const current = lines();
  const entry = JSON.parse(current[index] as string) as Record<string, unknown>;
  mutate(entry);
  current[index] = canonicalize(entry);
  writeFileSync(file, `${current.join('\n')}\n`, 'utf8');
}

describe('chain — append and verify', () => {
  it('treats an absent file as an empty chain whose head is the genesis value', () => {
    expect(readHead(file)).toEqual({ length: 0, head_hash: GENESIS_PREV_HASH });
    expect(verifyChain(file, 'record-entry')).toEqual({
      ok: true,
      length: 0,
      head_hash: GENESIS_PREV_HASH,
    });
  });

  it('links the first entry to 64 zeros and each later entry to its predecessor', () => {
    const first = appendEntry(file, 'record-entry', { world_id: 'w-demo', entry_id: 'rec_0' });
    expect(first.seq).toBe(0);
    expect(first.prev_hash).toBe(GENESIS_PREV_HASH);

    const second = appendEntry(file, 'record-entry', { world_id: 'w-demo', entry_id: 'rec_1' });
    expect(second.seq).toBe(1);
    expect(second.prev_hash).toBe(first.entry_hash);

    const result = verifyChain(file, 'record-entry');
    expect(result).toEqual({ ok: true, length: 2, head_hash: second.entry_hash });
    expect(readHead(file)).toEqual({ length: 2, head_hash: second.entry_hash });
  });

  it('hashes the entry minus entry_hash, including prev_hash', () => {
    const appended = appendEntry(file, 'record-entry', { world_id: 'w-demo', entry_id: 'rec_0' });
    const expected = digestFor('record-entry', {
      world_id: 'w-demo',
      entry_id: 'rec_0',
      seq: 0,
      prev_hash: GENESIS_PREV_HASH,
    });
    expect(appended.entry_hash).toBe(expected);
  });

  it('writes canonical lines, so a repaired entry reproduces identical bytes', () => {
    const appended = appendEntry(file, 'record-entry', { world_id: 'w-demo', entry_id: 'rec_0' });
    expect(appended.line.endsWith('\n')).toBe(true);
    expect(appended.line.trimEnd()).toBe(canonicalize(JSON.parse(appended.line)));
  });

  it('refuses a caller-supplied seq, prev_hash, or entry_hash', () => {
    for (const field of ['seq', 'prev_hash', 'entry_hash']) {
      expect(() => appendEntry(file, 'record-entry', { world_id: 'w-demo', [field]: 1 })).toThrow(ChainError);
    }
  });

  it('works for all three streams under their own domain tags', () => {
    for (const tag of ['wal-entry', 'record-entry', 'access-entry'] as const) {
      const streamFile = join(dir, `${tag}.jsonl`);
      appendEntry(streamFile, tag, { world_id: 'w-demo', n: 1 });
      expect(verifyChain(streamFile, tag).ok).toBe(true);
    }
  });
});

describe('chain — tamper detection', () => {
  it('reports the index of an in-line payload edit', () => {
    seed(3);
    rewriteLine(1, (entry) => {
      entry['entry_id'] = 'rec_tampered';
    });
    const result = verifyChain(file, 'record-entry');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.index).toBe(1);
    expect(result.reason).toBe('hash');
    expect(result.torn_tail).toBe(false);
    expect(result.good_length).toBe(1);
  });

  it('still fails when the forger recomputes the edited entry_hash', () => {
    seed(3);
    // A consistent forgery: the edited line hashes correctly, but the next line's
    // prev_hash no longer points at it.
    const current = lines();
    const entry = JSON.parse(current[1] as string) as Record<string, unknown>;
    delete entry['entry_hash'];
    entry['entry_id'] = 'rec_tampered';
    const forged = digestFor('record-entry', entry);
    current[1] = canonicalize({ ...entry, entry_hash: forged });
    writeFileSync(file, `${current.join('\n')}\n`, 'utf8');

    const result = verifyChain(file, 'record-entry');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.index).toBe(2);
    expect(result.reason).toBe('hash');
  });

  it('reports a seq break as seq, not as a hash failure', () => {
    seed(3);
    const current = lines();
    const entry = JSON.parse(current[1] as string) as Record<string, unknown>;
    delete entry['entry_hash'];
    entry['seq'] = 7;
    current[1] = canonicalize({ ...entry, entry_hash: digestFor('record-entry', entry) });
    writeFileSync(file, `${current.join('\n')}\n`, 'utf8');

    const result = verifyChain(file, 'record-entry');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.index).toBe(1);
    expect(result.reason).toBe('seq');
  });

  it('reports unparseable content as parse', () => {
    seed(2);
    const current = lines();
    current[0] = '{not json';
    writeFileSync(file, `${current.join('\n')}\n`, 'utf8');
    const result = verifyChain(file, 'record-entry');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result).toMatchObject({ index: 0, reason: 'parse', torn_tail: false });
  });

  it('fails when verified under the wrong domain tag', () => {
    seed(2);
    expect(verifyChain(file, 'record-entry').ok).toBe(true);
    const result = verifyChain(file, 'wal-entry');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.index).toBe(0);
    expect(result.reason).toBe('hash');
  });
});

describe('chain — torn tail', () => {
  it('distinguishes a clean tail truncation and names the point to truncate to', () => {
    seed(3);
    const before = verifyChain(file, 'record-entry');
    expect(before.ok).toBe(true);

    const size = statSync(file).size;
    truncateSync(file, size - 5); // a crash mid-append: last line, no trailing newline

    const result = verifyChain(file, 'record-entry');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.index).toBe(2);
    expect(result.torn_tail).toBe(true);
    expect(result.good_length).toBe(2);

    // "A crash can lose the last transaction, never corrupt an earlier one" (ADR-001 §2).
    truncateSync(file, result.good_bytes);
    const repaired = verifyChain(file, 'record-entry');
    expect(repaired).toEqual({ ok: true, length: 2, head_hash: result.good_head_hash });
  });

  it('does not call an in-line edit a torn tail even at the last line', () => {
    seed(3);
    rewriteLine(2, (entry) => {
      entry['entry_id'] = 'rec_tampered';
    });
    const result = verifyChain(file, 'record-entry');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.index).toBe(2);
    expect(result.torn_tail).toBe(false);
  });

  it('refuses to append onto an unrepaired torn tail', () => {
    seed(2);
    truncateSync(file, statSync(file).size - 5);
    expect(() => readHead(file)).toThrow(ChainError);
    let thrown: unknown;
    try {
      appendEntry(file, 'record-entry', { world_id: 'w-demo', entry_id: 'rec_x' });
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(ChainError);
    expect((thrown as ChainError).code).toBe('torn-tail');
  });
});
