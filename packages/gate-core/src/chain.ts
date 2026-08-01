// SPDX-License-Identifier: AGPL-3.0-only
/**
 * ADR-001 §2 / ADR-003 — append-only JSONL hash chains.
 *
 * One construction for all three streams (`wal`, `action`, `access`), separated only by
 * their ADR-007 domain tag:
 *
 *     entry_hash = H(domain || canonical(entry without entry_hash))
 *
 * with the entry including its `prev_hash`; the first entry's `prev_hash` is 64 zeros.
 * Lines are canonical JSON, so a repaired entry reproduces byte-identical output
 * (ADR-001 §9 step 4).
 *
 * `seq` and `prev_hash` are assigned by the writer, never by the caller: `seq` is the
 * entry's own zero-based index, which is what makes ADR-001 §9's contiguity check
 * decidable from the file alone.
 */
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeSync,
} from 'node:fs';
import { dirname } from 'node:path';

import { canonicalize } from './canonicalize.js';
import type { ChainDomainTag } from './domain.js';
import { isChainDomainTag } from './domain.js';
import { digestFor, isHexDigest, verifyDigest } from './hash.js';

/** The first entry's `prev_hash`, and the head hash of an empty chain. */
export const GENESIS_PREV_HASH = '0'.repeat(64);

export interface ChainHead {
  readonly length: number;
  readonly head_hash: string;
}

export interface AppendedEntry {
  readonly seq: number;
  readonly prev_hash: string;
  readonly entry_hash: string;
  /** The exact line written, including its trailing newline. */
  readonly line: string;
}

/** Why the first bad line is bad. */
export type ChainFailureReason = 'parse' | 'seq' | 'hash';

export interface ChainVerifyOk extends ChainHead {
  readonly ok: true;
}

export interface ChainVerifyFailure {
  readonly ok: false;
  /** Zero-based index of the first line that does not verify. */
  readonly index: number;
  readonly reason: ChainFailureReason;
  /**
   * True when the failure is a clean tail truncation — the last line of a file that does
   * not end in a newline, i.e. the signature of a crash mid-append. In-line tampering is
   * never a torn tail: it fails at a line the writer had already completed.
   */
  readonly torn_tail: boolean;
  /** Verified prefix: entry count, head hash, and the byte offset to truncate to. */
  readonly good_length: number;
  readonly good_head_hash: string;
  readonly good_bytes: number;
}

export type ChainVerifyResult = ChainVerifyOk | ChainVerifyFailure;

export class ChainError extends Error {
  readonly code: 'torn-tail' | 'malformed-head' | 'reserved-field' | 'unknown-domain';
  constructor(code: ChainError['code'], message: string) {
    super(message);
    this.name = 'ChainError';
    this.code = code;
  }
}

const RESERVED_FIELDS = ['seq', 'prev_hash', 'entry_hash'] as const;

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === null;
}

function assertChainDomain(domainTag: ChainDomainTag): void {
  if (!isChainDomainTag(domainTag)) {
    throw new ChainError('unknown-domain', `chain: ${String(domainTag)} is not a chain domain tag`);
  }
}

/** Split file text into lines, reporting whether the final line was terminated. */
function splitLines(raw: string): { lines: string[]; terminated: boolean } {
  const terminated = raw.endsWith('\n');
  const lines = raw.split('\n');
  if (terminated) lines.pop();
  return { lines, terminated };
}

/**
 * Current length and head hash. An absent or empty file is a chain of length 0 whose head
 * hash is the genesis value, so a first append links to 64 zeros without a special case.
 *
 * @throws {ChainError} on a torn tail — recovery (ADR-001 §9) is the caller's job, and an
 * append onto an unrepaired torn tail would bury the damage.
 */
export function readHead(file: string): ChainHead {
  if (!existsSync(file)) return { length: 0, head_hash: GENESIS_PREV_HASH };
  const raw = readFileSync(file, 'utf8');
  if (raw.length === 0) return { length: 0, head_hash: GENESIS_PREV_HASH };

  const { lines, terminated } = splitLines(raw);
  if (!terminated) {
    throw new ChainError('torn-tail', `chain: ${file} has an unterminated final line; run recovery first`);
  }
  const last = lines[lines.length - 1];
  if (last === undefined) return { length: 0, head_hash: GENESIS_PREV_HASH };

  let parsed: unknown;
  try {
    parsed = JSON.parse(last);
  } catch {
    throw new ChainError('malformed-head', `chain: ${file} has an unparseable final line`);
  }
  if (!isPlainRecord(parsed) || !isHexDigest(parsed['entry_hash'])) {
    throw new ChainError('malformed-head', `chain: ${file} final line has no valid entry_hash`);
  }
  return { length: lines.length, head_hash: parsed['entry_hash'] };
}

/**
 * Append one entry and fsync before returning. The caller supplies the payload only;
 * `seq`, `prev_hash`, and `entry_hash` are the chain's to assign.
 */
export function appendEntry(
  file: string,
  domainTag: ChainDomainTag,
  entry: Record<string, unknown>,
): AppendedEntry {
  assertChainDomain(domainTag);
  if (!isPlainRecord(entry)) {
    throw new TypeError('appendEntry: entry must be a plain object');
  }
  for (const field of RESERVED_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(entry, field)) {
      throw new ChainError('reserved-field', `appendEntry: ${field} is assigned by the chain, not the caller`);
    }
  }

  const head = readHead(file);
  const body: Record<string, unknown> = { ...entry, seq: head.length, prev_hash: head.head_hash };
  const entryHash = digestFor(domainTag, body);
  const line = `${canonicalize({ ...body, entry_hash: entryHash })}\n`;

  mkdirSync(dirname(file), { recursive: true });
  const fd = openSync(file, 'a');
  try {
    writeSync(fd, line, null, 'utf8');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }

  return { seq: head.length, prev_hash: head.head_hash, entry_hash: entryHash, line };
}

/**
 * Recompute the chain from entry 0, link by link. Returns the head on success, or the
 * first failing index with its reason — and, for a failure, the verified prefix plus the
 * byte offset a torn tail would be truncated to.
 */
export function verifyChain(file: string, domainTag: ChainDomainTag): ChainVerifyResult {
  assertChainDomain(domainTag);
  if (!existsSync(file)) return { ok: true, length: 0, head_hash: GENESIS_PREV_HASH };
  const raw = readFileSync(file, 'utf8');
  if (raw.length === 0) return { ok: true, length: 0, head_hash: GENESIS_PREV_HASH };

  const { lines, terminated } = splitLines(raw);

  let prevHash = GENESIS_PREV_HASH;
  let goodBytes = 0;
  let goodLength = 0;
  let goodHeadHash = GENESIS_PREV_HASH;

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    const isFinalLine = index === lines.length - 1;
    const fail = (reason: ChainFailureReason): ChainVerifyFailure => ({
      ok: false,
      index,
      reason,
      torn_tail: isFinalLine && !terminated,
      good_length: goodLength,
      good_head_hash: goodHeadHash,
      good_bytes: goodBytes,
    });

    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      return fail('parse');
    }
    if (!isPlainRecord(parsed)) return fail('parse');

    const { entry_hash: entryHash, ...body } = parsed;
    if (!isHexDigest(entryHash)) return fail('parse');
    if (body['seq'] !== index) return fail('seq');
    // Checked separately from the digest so a consistently re-hashed forged prefix — one
    // whose entries verify against each other but not against their predecessor — still fails.
    if (body['prev_hash'] !== prevHash) return fail('hash');

    let computed: string;
    try {
      computed = digestFor(domainTag, body);
    } catch {
      // A line outside the canonicalization subset cannot be hashed, so it cannot verify.
      return fail('parse');
    }
    if (!verifyDigest(entryHash, computed)) return fail('hash');

    prevHash = entryHash;
    goodBytes += Buffer.byteLength(line, 'utf8') + 1;
    goodLength = index + 1;
    goodHeadHash = entryHash;
  }

  return { ok: true, length: lines.length, head_hash: prevHash };
}
